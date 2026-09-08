"""Run one approved vendor parser through the generic Spark/HDFS analytics path."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


SPARK_MCP_URL = os.environ.get("SPARK_MCP_URL", "http://127.0.0.1:8001/mcp")
SKILL_MCP_URL = os.environ.get("SKILL_MCP_URL", "http://127.0.0.1:8003/mcp")
SOURCE_NAME = os.environ["SECURITY_SOURCE_NAME"]
SOURCES = json.loads(os.environ.get("SECURITY_SOURCES_JSON", "null"))
if SOURCES is not None and (not isinstance(SOURCES, list) or len(SOURCES) < 3):
    raise ValueError("SECURITY_SOURCES_JSON must be a JSON array with at least 3 sources")
PROBE_SOURCE_NAME = SOURCES[0]["source_name"] if SOURCES else SOURCE_NAME
SOURCE_PATH = Path(os.environ.get("SECURITY_SOURCE_PATH", f"/imports/{PROBE_SOURCE_NAME}"))
SKILL_NAME = os.environ["SECURITY_SKILL_NAME"]
PARSER_ID = os.environ["SECURITY_PARSER_ID"]
VENDOR = os.environ["SECURITY_VENDOR"]
PRODUCT = os.environ["SECURITY_PRODUCT"]
LOG_TYPE = os.environ.get("SECURITY_LOG_TYPE", "traffic")
EXPECTED_RECORDS = int(os.environ["SECURITY_EXPECTED_RECORDS"])
RUN_ID = os.environ["SECURITY_RUN_ID"]
HDFS_AUTHORITY = os.environ.get("HDFS_AUTHORITY", "namenode:9000")

if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", RUN_ID):
    raise ValueError("SECURITY_RUN_ID must be lowercase kebab-case")

VIRTUAL_ROOT = f"/generic-security/{RUN_ID}"
INPUT_VIRTUAL = f"{VIRTUAL_ROOT}/input" if SOURCES else f"{VIRTUAL_ROOT}/input/events.log"
CURATED_VIRTUAL = f"{VIRTUAL_ROOT}/curated"
REPORT_VIRTUAL = f"{VIRTUAL_ROOT}/report"
SPARK_ROOT = f"hdfs://{HDFS_AUTHORITY}/mcp{VIRTUAL_ROOT}"
JOB_NAME = f"generic_security_{RUN_ID.replace('-', '_')}.py"


def result_data(result: Any) -> Any:
    if result.isError:
        message = "\n".join(getattr(item, "text", str(item)) for item in result.content)
        raise RuntimeError(message)
    if result.structuredContent is not None:
        return result.structuredContent.get("result", result.structuredContent)
    return json.loads(result.content[0].text)


def probe_samples(limit: int = 20) -> list[str]:
    if not SOURCE_PATH.is_file():
        raise FileNotFoundError(str(SOURCE_PATH))
    with SOURCE_PATH.open(encoding="utf-8", errors="strict") as source:
        samples = [line.rstrip("\n") for _, line in zip(range(limit), source) if line.strip()]
    if not samples:
        raise ValueError("source contains no records")
    return samples


async def skill_phase(samples: list[str]) -> tuple[str, dict[str, Any]]:
    async with streamablehttp_client(SKILL_MCP_URL) as streams:
        read_stream, write_stream, _ = streams
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            resolved = result_data(
                await session.call_tool(
                    "log_skill_resolve",
                    {
                        "sample": samples[0],
                        "vendor": VENDOR,
                        "product": PRODUCT,
                        "log_type": LOG_TYPE,
                    },
                )
            )
            selected = resolved.get("selected")
            if not selected or selected.get("skill") != SKILL_NAME or selected.get(
                "parser_id"
            ) != PARSER_ID:
                raise RuntimeError(f"unexpected parser resolution: {resolved}")
            tested = result_data(
                await session.call_tool(
                    "log_skill_test_parser",
                    {
                        "skill_name": SKILL_NAME,
                        "parser_id": PARSER_ID,
                        "samples": samples,
                    },
                )
            )
            if tested["failed"] or tested["passed"] != len(samples):
                raise RuntimeError(f"parser probe failed: {tested}")
            rendered = result_data(
                await session.call_tool(
                    "log_skill_render_spark_job",
                    {"skill_name": SKILL_NAME, "parser_id": PARSER_ID},
                )
            )
            validated = result_data(
                await session.call_tool(
                    "log_skill_validate_spark_job",
                    {
                        "skill_name": SKILL_NAME,
                        "parser_id": PARSER_ID,
                        "code": rendered["code"],
                    },
                )
            )
            if not validated["valid"]:
                raise RuntimeError(f"Spark code validation failed: {validated}")
            return rendered["code"], {
                "parser_id": PARSER_ID,
                "probe_passed": tested["passed"],
                "probe_total": tested["total"],
                "template_sha256": rendered["template_sha256"],
                "parser_sha256": rendered["parser_sha256"],
                "code_sha256": rendered["code_sha256"],
                "validation": validated,
            }


async def spark_phase(code: str) -> tuple[dict[str, Any], dict[str, Any]]:
    code_sha256 = hashlib.sha256(code.encode()).hexdigest()
    async with streamablehttp_client(SPARK_MCP_URL) as streams:
        read_stream, write_stream, _ = streams
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            spark_cluster = result_data(await session.call_tool("spark_cluster_status"))
            hdfs_cluster = result_data(await session.call_tool("hdfs_cluster_status"))
            bindings = SOURCES or [{"source_name": SOURCE_NAME}]
            imports = []
            for binding in bindings:
                destination = (
                    f"{INPUT_VIRTUAL}/{binding['source_name']}"
                    if SOURCES
                    else INPUT_VIRTUAL
                )
                imported = result_data(
                    await session.call_tool(
                        "hdfs_import_file",
                        {
                            "source_name": binding["source_name"],
                            "destination": destination,
                            "overwrite": False,
                        },
                    )
                )
                if not imported.get("destination_verified"):
                    raise RuntimeError(f"HDFS import was not verified: {imported}")
                if binding.get("sha256") and imported.get("sha256") != binding["sha256"]:
                    raise RuntimeError(f"source SHA mismatch: {binding['source_name']}")
                if binding.get("bytes") and imported.get("bytes") != binding["bytes"]:
                    raise RuntimeError(f"source byte count mismatch: {binding['source_name']}")
                imports.append(imported)
            saved = result_data(
                await session.call_tool(
                    "spark_save_job",
                    {"filename": JOB_NAME, "code": code, "overwrite": False},
                )
            )
            readback = result_data(
                await session.call_tool("spark_read_job", {"filename": JOB_NAME})
            )
            readback_sha = hashlib.sha256(readback["code"].encode()).hexdigest()
            if readback_sha != code_sha256:
                raise RuntimeError("saved Spark job SHA does not match rendered source")
            syntax = result_data(
                await session.call_tool("spark_validate_job", {"filename": JOB_NAME})
            )
            if not syntax["valid_python"] or not syntax["imports_pyspark"]:
                raise RuntimeError(f"Spark syntax validation failed: {syntax}")
            idempotency_key = f"generic-security-{RUN_ID}"
            submitted = result_data(
                await session.call_tool(
                    "spark_submit_job",
                    {
                        "filename": JOB_NAME,
                        "arguments": [
                            f"{SPARK_ROOT}/input" if SOURCES else f"{SPARK_ROOT}/input/events.log",
                            f"{SPARK_ROOT}/curated",
                            f"{SPARK_ROOT}/report",
                        ],
                        "conf": {"spark.sql.adaptive.enabled": "true"},
                        "expected_sha256": code_sha256,
                        "idempotency_key": idempotency_key,
                    },
                )
            )
            job_id = submitted["job_id"]
            status: dict[str, Any] = submitted
            for _ in range(180):
                status = result_data(
                    await session.call_tool("spark_job_status", {"job_id": job_id})
                )
                if status["status"] not in {"STARTING", "RUNNING"}:
                    break
                await asyncio.sleep(2)
            if status["status"] != "SUCCEEDED" or status.get("exit_code") != 0:
                logs = result_data(
                    await session.call_tool(
                        "spark_job_logs", {"job_id": job_id, "tail_lines": 200}
                    )
                )
                raise RuntimeError(json.dumps({"status": status, "logs": logs}, indent=2))
            curated_success = result_data(
                await session.call_tool(
                    "hdfs_stat", {"path": f"{CURATED_VIRTUAL}/_SUCCESS"}
                )
            )
            report_success = result_data(
                await session.call_tool(
                    "hdfs_stat", {"path": f"{REPORT_VIRTUAL}/_SUCCESS"}
                )
            )
            report_files = result_data(
                await session.call_tool("hdfs_list", {"path": REPORT_VIRTUAL})
            )
            parts = [
                item for item in report_files if item.get("pathSuffix", "").startswith("part-")
            ]
            if len(parts) != 1:
                raise RuntimeError(f"expected one report part, got {len(parts)}")
            report_text = result_data(
                await session.call_tool(
                    "hdfs_read_text",
                    {"path": f"{REPORT_VIRTUAL}/{parts[0]['pathSuffix']}"},
                )
            )
            report = json.loads(report_text["text"])
            return report, {
                "spark_cluster": spark_cluster,
                "hdfs_cluster": hdfs_cluster,
                "input_import": imports[0] if not SOURCES else {"all_verified": True, "sources": imports},
                "saved_job": saved,
                "readback_sha256": readback_sha,
                "submission": submitted,
                "status": status,
                "curated_success": curated_success,
                "report_success": report_success,
                "report_part": parts[0],
            }


async def validate_report(report: dict[str, Any]) -> dict[str, Any]:
    async with streamablehttp_client(SKILL_MCP_URL) as streams:
        read_stream, write_stream, _ = streams
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            validated = result_data(
                await session.call_tool("log_skill_validate_report", {"report": report})
            )
    if not validated["valid"]:
        raise RuntimeError(f"report validation failed: {validated}")
    return validated


async def main() -> None:
    samples = probe_samples()
    code, skill_evidence = await skill_phase(samples)
    report, execution_evidence = await spark_phase(code)
    report_validation = await validate_report(report)
    total = report.get("total_evidence_records", report.get("total_records"))
    if total != EXPECTED_RECORDS:
        raise RuntimeError(
            f"expected {EXPECTED_RECORDS} records, got {total}"
        )
    print(
        json.dumps(
            {
                "outcome": "SUCCESS",
                "skill": skill_evidence,
                "execution": execution_evidence,
                "report_validation": report_validation,
                "report": report,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(asyncio.wait_for(main(), timeout=600))
