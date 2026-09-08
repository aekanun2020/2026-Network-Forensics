"""End-to-end PAN-OS batch proof using both project MCP servers."""

from __future__ import annotations

import asyncio
import json
import os
from datetime import timedelta
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


SPARK_MCP_URL = os.environ.get("SPARK_MCP_URL", "http://127.0.0.1:8000/mcp")
SKILL_MCP_URL = os.environ.get(
    "SKILL_MCP_URL", "http://security-log-skills-mcp:8000/mcp"
)
SOURCE_NAME = os.environ.get("PANOS_SOURCE_NAME", "panos-traffic-100k.log")
EXPECTED_RECORDS = int(os.environ.get("PANOS_EXPECTED_RECORDS", "100000"))
SOURCE_PATH = Path("/imports") / SOURCE_NAME
HDFS_INPUT = "/security-logs/panos/raw/panos-traffic-100k.log"
HDFS_CURATED = "hdfs://namenode:9000/mcp/security-logs/panos/curated/traffic-100k"
HDFS_REPORT = "/security-logs/panos/reports/traffic-100k"
JOB_NAME = "panos_traffic_batch_analysis.py"


def result_data(result: Any) -> Any:
    if result.isError:
        message = "\n".join(getattr(item, "text", str(item)) for item in result.content)
        raise RuntimeError(message)
    if result.structuredContent is not None:
        return result.structuredContent.get("result", result.structuredContent)
    return json.loads(result.content[0].text)


async def fetch_parser_and_probe() -> tuple[dict[str, Any], str, dict[str, Any]]:
    if not SOURCE_PATH.is_file():
        raise FileNotFoundError(f"staged import does not exist: {SOURCE_PATH}")
    samples = []
    with SOURCE_PATH.open(encoding="utf-8", errors="strict") as source:
        for _ in range(20):
            line = source.readline().rstrip("\n")
            if not line:
                break
            samples.append(line)
    if not samples:
        raise ValueError("source contains no records")

    async with streamablehttp_client(SKILL_MCP_URL) as streams:
        read_stream, write_stream, _ = streams
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            resolved = result_data(
                await session.call_tool(
                    "log_skill_resolve",
                    {
                        "sample": samples[0],
                        "vendor": "paloalto",
                        "product": "panos",
                        "log_type": "traffic",
                    },
                )
            )
            selected = resolved.get("selected")
            if not selected or selected["parser_id"] != "paloalto-panos-11x-traffic":
                raise RuntimeError(f"unexpected parser resolution: {resolved}")
            tested = result_data(
                await session.call_tool(
                    "log_skill_test_parser",
                    {
                        "skill_name": selected["skill"],
                        "parser_id": selected["parser_id"],
                        "samples": samples,
                    },
                )
            )
            if tested["failed"]:
                raise RuntimeError(f"skill parser rejected probe samples: {tested}")
            skill = result_data(
                await session.call_tool(
                    "log_skill_get",
                    {"skill_name": selected["skill"], "include_body": False},
                )
            )
            rendered = result_data(
                await session.call_tool(
                    "log_skill_render_spark_job",
                    {
                        "skill_name": selected["skill"],
                        "parser_id": selected["parser_id"],
                    },
                )
            )
            job_validation = result_data(
                await session.call_tool(
                    "log_skill_validate_spark_job",
                    {
                        "skill_name": selected["skill"],
                        "parser_id": selected["parser_id"],
                        "code": rendered["code"],
                    },
                )
            )
            if not job_validation["valid"]:
                raise RuntimeError(
                    f"trusted Spark job failed Skill MCP validation: {job_validation}"
                )
    parser = next(item for item in skill["parsers"] if item["id"] == selected["parser_id"])
    return parser, rendered["code"], {
        "selected": selected,
        "probe_samples": tested["total"],
        "probe_passed": tested["passed"],
        "template_sha256": rendered["template_sha256"],
        "parser_sha256": rendered["parser_sha256"],
        "code_sha256": rendered["code_sha256"],
        "trusted_job_valid": job_validation["valid"],
    }


async def run_spark_workflow(parser: dict[str, Any], code: str) -> dict[str, Any]:
    async with streamablehttp_client(SPARK_MCP_URL) as streams:
        read_stream, write_stream, _ = streams
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            spark_cluster = result_data(await session.call_tool("spark_cluster_status"))
            hdfs_cluster = result_data(await session.call_tool("hdfs_cluster_status"))
            imported = result_data(
                await session.call_tool(
                    "hdfs_import_file",
                    {
                        "source_name": SOURCE_NAME,
                        "destination": HDFS_INPUT,
                        "overwrite": True,
                    },
                )
            )
            result_data(
                await session.call_tool(
                    "spark_save_job",
                    {"filename": JOB_NAME, "code": code, "overwrite": True},
                )
            )
            validated = result_data(
                await session.call_tool("spark_validate_job", {"filename": JOB_NAME})
            )
            if not validated["valid_python"] or not validated["imports_pyspark"]:
                raise RuntimeError(f"generated Spark job did not validate: {validated}")
            submitted = result_data(
                await session.call_tool(
                    "spark_submit_job",
                    {
                        "filename": JOB_NAME,
                        "arguments": [
                            "hdfs://namenode:9000/mcp" + HDFS_INPUT,
                            HDFS_CURATED,
                            "hdfs://namenode:9000/mcp" + HDFS_REPORT,
                        ],
                        "conf": {"spark.sql.adaptive.enabled": "true"},
                    },
                )
            )
            job_id = submitted["job_id"]
            for _ in range(180):
                status = result_data(
                    await session.call_tool("spark_job_status", {"job_id": job_id})
                )
                if status["status"] != "RUNNING":
                    break
                await asyncio.sleep(2)
            if status["status"] != "SUCCEEDED":
                logs = result_data(
                    await session.call_tool(
                        "spark_job_logs", {"job_id": job_id, "tail_lines": 300}
                    )
                )
                raise RuntimeError(json.dumps({"status": status, "logs": logs}, indent=2))

            report_files = result_data(
                await session.call_tool("hdfs_list", {"path": HDFS_REPORT})
            )
            part = next(item["pathSuffix"] for item in report_files if item["pathSuffix"].startswith("part-"))
            report_file = result_data(
                await session.call_tool(
                    "hdfs_read_text", {"path": f"{HDFS_REPORT}/{part}"}
                )
            )
            curated = result_data(
                await session.call_tool(
                    "hdfs_stat", {"path": "/security-logs/panos/curated/traffic-100k"}
                )
            )
            report = json.loads(report_file["text"])
            if report["total_records"] != EXPECTED_RECORDS:
                raise RuntimeError(
                    f"expected {EXPECTED_RECORDS} records, got {report['total_records']}"
                )
            if report["parse_quality"] != {"parsed": EXPECTED_RECORDS}:
                raise RuntimeError(f"unexpected parse quality: {report['parse_quality']}")
            return {
                "cluster": {
                    "spark_status": spark_cluster["status"],
                    "spark_workers": len(spark_cluster["workers"]),
                    "hdfs_datanodes": hdfs_cluster["NumLiveDataNodes"],
                },
                "hdfs_import": imported,
                "spark_job": status,
                "curated_hdfs": curated,
                "report": report,
            }


async def validate_report_contract(report: dict[str, Any]) -> dict[str, Any]:
    async with streamablehttp_client(SKILL_MCP_URL) as streams:
        read_stream, write_stream, _ = streams
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            validation = result_data(
                await session.call_tool(
                    "log_skill_validate_report",
                    {"report": report},
                )
            )
    if not validation["valid"]:
        raise RuntimeError(f"Spark report failed Skill MCP validation: {validation}")
    return validation


async def main() -> None:
    parser, code, skill_check = await fetch_parser_and_probe()
    spark_result = await run_spark_workflow(parser, code)
    skill_check["report_validation"] = await validate_report_contract(
        spark_result["report"]
    )
    print(json.dumps({"skill_mcp": skill_check, "spark_hdfs_mcp": spark_result}, indent=2))


if __name__ == "__main__":
    asyncio.run(asyncio.wait_for(main(), timeout=timedelta(minutes=10).total_seconds()))
