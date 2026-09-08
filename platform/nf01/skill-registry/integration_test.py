"""Container-local MCP smoke test for the security-log skill registry."""

import asyncio
from pathlib import Path

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def main() -> None:
    async with streamable_http_client("http://127.0.0.1:8000/mcp") as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = {tool.name for tool in tools.tools}
            expected = {
                "log_skill_list",
                "log_skill_resolve",
                "log_skill_validate",
                "log_skill_test_parser",
                "log_skill_save_draft",
                "log_skill_list_resources",
                "log_skill_read_resource",
                "log_skill_render_spark_job",
                "log_skill_validate_spark_job",
                "log_skill_validate_report",
            }
            assert expected <= names, (expected, names)

            listed = await session.call_tool("log_skill_list", {})
            assert "parse-paloalto-panos-logs" in str(listed.structuredContent)
            assert "parse-huawei-security-logs" in str(listed.structuredContent)

            palo = Path("/skills/parse-paloalto-panos-logs/assets/samples/panos-traffic.log").read_text().strip()
            resolved = await session.call_tool("log_skill_resolve", {"sample": palo})
            assert "paloalto-panos-11x-traffic" in str(resolved.structuredContent)

            huawei = Path("/skills/parse-huawei-security-logs/assets/samples/huawei-system.log").read_text().strip()
            resolved = await session.call_tool("log_skill_resolve", {"sample": huawei})
            assert "huawei-vrp-system" in str(resolved.structuredContent)

            for skill_name in (
                "analyze-security-logs-with-spark",
                "normalize-security-logs",
                "parse-paloalto-panos-logs",
                "parse-huawei-security-logs",
            ):
                validated = await session.call_tool("log_skill_validate", {"skill_name": skill_name})
                assert "'valid': True" in str(validated.structuredContent), validated

            resources = await session.call_tool(
                "log_skill_list_resources",
                {"skill_name": "analyze-security-logs-with-spark"},
            )
            assert "spark_security_report_job.py.tmpl" in str(resources.structuredContent)
            assert "report-contract-v1.json" in str(resources.structuredContent)

            rendered = await session.call_tool(
                "log_skill_render_spark_job",
                {
                    "skill_name": "parse-paloalto-panos-logs",
                    "parser_id": "paloalto-panos-11x-traffic",
                },
            )
            assert "paloalto-panos-11x-traffic" in str(rendered.structuredContent)
            assert "'execution': 'not executed'" in str(rendered.structuredContent)

    print("security-log-skills MCP integration test passed")


if __name__ == "__main__":
    asyncio.run(main())
