import asyncio
import hashlib
import json
import tempfile
import uuid
import warnings
from datetime import timedelta
from pathlib import Path

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


EXPECTED_TOOLS = {
    "spark_save_job",
    "spark_read_job",
    "spark_replace_job_text",
    "spark_validate_job",
    "spark_submit_job",
    "spark_job_status",
    "spark_job_logs",
    "spark_cancel_job",
    "spark_list_jobs",
    "spark_cluster_status",
    "hdfs_list",
    "hdfs_stat",
    "hdfs_mkdir",
    "hdfs_write_text",
    "hdfs_read_text",
    "hdfs_delete",
    "hdfs_import_file",
    "hdfs_cluster_status",
}


def data(result):
    if result.isError:
        message = "\n".join(getattr(item, "text", str(item)) for item in result.content)
        raise RuntimeError(message)
    if result.structuredContent is not None:
        payload = result.structuredContent.get("result", result.structuredContent)
        return payload
    return json.loads(result.content[0].text)


async def assert_local_launch_failure_contract():
    """Exercise the durable return contract that cannot be induced over MCP."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        import server as local_server

    original_jobs = local_server.JOBS_DIR
    original_state = local_server.STATE_DIR
    original_submit = local_server.SPARK_SUBMIT
    with tempfile.TemporaryDirectory(prefix="mcp-launch-failure-test-") as tmp:
        root = Path(tmp)
        local_server.JOBS_DIR = (root / "jobs").resolve()
        local_server.STATE_DIR = (root / "state").resolve()
        local_server.SPARK_SUBMIT = str(root / "missing-spark-submit")
        local_server.JOBS_DIR.mkdir()
        local_server.STATE_DIR.mkdir()
        try:
            code = b"from pyspark.sql import SparkSession\n"
            filename = "launch_failure.py"
            (local_server.JOBS_DIR / filename).write_bytes(code)
            code_sha256 = hashlib.sha256(code).hexdigest()
            request = {
                "filename": filename,
                "expected_sha256": code_sha256,
                "idempotency_key": f"launch-failure:{uuid.uuid4()}",
            }
            failed = await local_server.spark_submit_job(**request)
            assert failed["status"] == "LAUNCH_FAILED"
            assert failed["deduplicated"] is False
            assert failed["finished_at"]
            assert failed["launch_error"].startswith("FileNotFoundError:")
            assert not list(local_server.STATE_DIR.glob("*.job.py"))

            (local_server.JOBS_DIR / filename).unlink()
            replayed = await local_server.spark_submit_job(**request)
            assert replayed["status"] == "LAUNCH_FAILED"
            assert replayed["deduplicated"] is True
            assert replayed["job_id"] == failed["job_id"]
        finally:
            local_server.JOBS_DIR = original_jobs
            local_server.STATE_DIR = original_state
            local_server.SPARK_SUBMIT = original_submit


async def main():
    await assert_local_launch_failure_contract()
    async with streamablehttp_client("http://127.0.0.1:8000/mcp") as streams:
        read_stream, write_stream, _ = streams
        async with ClientSession(read_stream, write_stream) as session:
            initialized = await session.initialize()
            assert initialized.instructions

            tools = await session.list_tools()
            names = {tool.name for tool in tools.tools}
            assert names == EXPECTED_TOOLS, sorted(names ^ EXPECTED_TOOLS)
            descriptions = {tool.name: tool.description or "" for tool in tools.tools}
            assert "do not include the /mcp prefix" in descriptions["hdfs_stat"]
            assert "returned ``destination`` is the physical HDFS" in descriptions[
                "hdfs_import_file"
            ]
            assert "Never pass an HDFS MCP virtual path" in descriptions[
                "spark_submit_job"
            ]

            spark = data(await session.call_tool("spark_cluster_status"))
            assert spark["status"] == "ALIVE"
            assert len(spark["workers"]) == 2

            hdfs = data(await session.call_tool("hdfs_cluster_status"))
            assert hdfs["NumLiveDataNodes"] == 2
            assert hdfs["NumDeadDataNodes"] == 0
            assert hdfs["MissingBlocks"] == 0

            await session.call_tool("hdfs_mkdir", {"path": "/integration"})
            written = data(
                await session.call_tool(
                    "hdfs_write_text",
                    {
                        "path": "/integration/hello.txt",
                        "text": "hello from MCP",
                        "overwrite": True,
                    },
                )
            )
            assert written["path"] == "/mcp/integration/hello.txt"
            read = data(
                await session.call_tool(
                    "hdfs_read_text", {"path": "/integration/hello.txt"}
                )
            )
            assert read["text"] == "hello from MCP"

            import_content = b"stable MCP import\n"
            import_name = "mcp-integration-import.txt"
            Path(f"/imports/{import_name}").write_bytes(import_content)
            imported = data(
                await session.call_tool(
                    "hdfs_import_file",
                    {
                        "source_name": import_name,
                        "destination": "/integration/imported.txt",
                        "overwrite": True,
                    },
                )
            )
            assert imported["bytes"] == len(import_content)
            assert imported["sha256"] == hashlib.sha256(import_content).hexdigest()
            assert imported["destination_bytes"] == len(import_content)
            assert imported["destination_sha256"] == imported["sha256"]
            assert imported["destination_verified"] is True
            assert imported["source_stable"] is True
            assert imported["reused"] is False
            replayed_import = data(
                await session.call_tool(
                    "hdfs_import_file",
                    {
                        "source_name": import_name,
                        "destination": "/integration/imported.txt",
                        "overwrite": False,
                    },
                )
            )
            assert replayed_import["reused"] is True
            assert replayed_import["sha256"] == imported["sha256"]
            assert replayed_import["destination_sha256"] == imported["sha256"]
            imported_read = data(
                await session.call_tool(
                    "hdfs_read_text", {"path": "/integration/imported.txt"}
                )
            )
            assert imported_read["text"] == import_content.decode()
            import_listing = data(
                await session.call_tool("hdfs_list", {"path": "/integration"})
            )
            assert not [
                item
                for item in import_listing
                if ".import-" in item.get("pathSuffix", "")
                or ".backup-" in item.get("pathSuffix", "")
            ]

            code = """from pyspark.sql import SparkSession

spark = SparkSession.builder.appName("mcp-integration-test").getOrCreate()
path = "hdfs://namenode:9000/mcp/integration/spark-output"
spark.range(10).write.mode("overwrite").parquet(path)
assert spark.read.parquet(path).count() == 10
print("MCP_SPARK_HDFS_OK")
spark.stop()
"""
            saved_result = data(
                await session.call_tool(
                    "spark_save_job",
                    {
                        "filename": "mcp_integration_test.py",
                        "code": code,
                        "overwrite": True,
                    },
                )
            )
            assert saved_result["sha256"] == hashlib.sha256(code.encode()).hexdigest()
            saved = data(
                await session.call_tool(
                    "spark_read_job", {"filename": "mcp_integration_test.py"}
                )
            )
            assert saved["code"] == code
            repaired = data(
                await session.call_tool(
                    "spark_replace_job_text",
                    {
                        "filename": "mcp_integration_test.py",
                        "old_text": 'appName("mcp-integration-test")',
                        "new_text": 'appName("mcp-integration-test-patched")',
                    },
                )
            )
            assert repaired["replacements"] == 1
            validated = data(
                await session.call_tool(
                    "spark_validate_job", {"filename": "mcp_integration_test.py"}
                )
            )
            assert validated["imports_pyspark"] is True
            patched_code = code.replace(
                'appName("mcp-integration-test")',
                'appName("mcp-integration-test-patched")',
            )
            patched_sha256 = hashlib.sha256(patched_code.encode()).hexdigest()
            jobs_before_mismatch = data(
                await session.call_tool("spark_list_jobs", {"limit": 100})
            )
            mismatch = await session.call_tool(
                "spark_submit_job",
                {
                    "filename": "mcp_integration_test.py",
                    "expected_sha256": "0" * 64,
                    "idempotency_key": f"mcp-integration-mismatch:{uuid.uuid4()}",
                },
            )
            assert mismatch.isError
            assert "SHA-256 mismatch" in " ".join(
                getattr(item, "text", str(item)) for item in mismatch.content
            )
            jobs_after_mismatch = data(
                await session.call_tool("spark_list_jobs", {"limit": 100})
            )
            assert {
                item["job_id"] for item in jobs_before_mismatch
            } == {item["job_id"] for item in jobs_after_mismatch}

            idempotency_key = f"mcp-integration:{uuid.uuid4()}"
            submit_request = {
                "filename": "mcp_integration_test.py",
                "expected_sha256": patched_sha256,
                "idempotency_key": idempotency_key,
            }
            submitted = data(
                await session.call_tool("spark_submit_job", submit_request)
            )
            assert submitted["deduplicated"] is False
            assert submitted["code_sha256"] == patched_sha256
            assert submitted["request_sha256"]
            assert submitted["idempotency_key"] == idempotency_key
            assert submitted["code_snapshot"].endswith(".job.py")
            assert submitted["boot_id"]
            job_id = submitted["job_id"]
            conflict = await session.call_tool(
                "spark_submit_job",
                {**submit_request, "arguments": ["different-request"]},
            )
            assert conflict.isError
            assert "different Spark request" in " ".join(
                getattr(item, "text", str(item)) for item in conflict.content
            )
            restored = data(
                await session.call_tool(
                    "spark_replace_job_text",
                    {
                        "filename": "mcp_integration_test.py",
                        "old_text": 'appName("mcp-integration-test-patched")',
                        "new_text": 'appName("mcp-integration-test")',
                    },
                )
            )
            assert restored["replacements"] == 1
            duplicate = data(
                await session.call_tool("spark_submit_job", submit_request)
            )
            assert duplicate["deduplicated"] is True
            assert duplicate["job_id"] == job_id
            assert duplicate["code_sha256"] == patched_sha256
            for _ in range(60):
                status = data(
                    await session.call_tool("spark_job_status", {"job_id": job_id})
                )
                if status["status"] != "RUNNING":
                    break
                await asyncio.sleep(1)
            assert status["status"] == "SUCCEEDED", status
            assert status["code_sha256"] == patched_sha256
            assert status["request_sha256"] == submitted["request_sha256"]
            logs = data(
                await session.call_tool(
                    "spark_job_logs", {"job_id": job_id, "tail_lines": 200}
                )
            )
            assert any("MCP_SPARK_HDFS_OK" in line for line in logs["lines"])
            print(
                json.dumps(
                    {
                        "protocol": initialized.protocolVersion,
                        "tools": len(names),
                        "spark_workers": len(spark["workers"]),
                        "hdfs_datanodes": hdfs["NumLiveDataNodes"],
                        "spark_job": status["status"],
                        "hdfs_roundtrip": read["text"],
                        "hdfs_import_sha256": imported["sha256"],
                        "spark_submit_deduplicated": duplicate["deduplicated"],
                    },
                    indent=2,
                )
            )


if __name__ == "__main__":
    asyncio.run(asyncio.wait_for(main(), timeout=timedelta(minutes=2).total_seconds()))
