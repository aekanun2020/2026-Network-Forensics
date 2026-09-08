"""Integration checks against the real MCP endpoint and supplied HDFS F1-F6 files.

Does not create fixtures, mock services, invoke a model, or replace Spark analysis.
"""
import argparse
import asyncio
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import zipfile

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

NAMES = ["coherent-course-100k.pcap.zip", "coherent-pcap-zeek-dns-120.zip",
         "coherent-pcap-zeek-conn-100k.zip", "coherent-pcap-netflow-v5-100k.zip",
         "coherent-pcap-suricata-alerts-340.zip", "coherent-pcap-fortigate-100k.zip"]


async def run(args):
    require = lambda yes, message: None if yes else fail(message)
    require(not args.output.exists(), "Choose a new output file")
    audit = {"started_at": datetime.now(timezone.utc).isoformat(), "endpoint": args.endpoint,
             "model_calls": 0, "kind": "real-MCP-HDFS-integration", "checks": []}
    paths = []
    async with streamablehttp_client(args.endpoint) as (r, w, _):
        async with ClientSession(r, w, read_timeout_seconds=timedelta(seconds=300)) as session:
            await session.initialize()
            async def call(name, arguments):
                result = await session.call_tool(name, arguments)
                require(not result.isError, str(result.content))
                data = result.structuredContent or json.loads(result.content[0].text)
                audit["checks"].append({"tool": name, "arguments": arguments, "result": data})
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(audit, ensure_ascii=False, indent=2) + "\n")
                return data
            for archive in NAMES:
                with zipfile.ZipFile(args.samples / archive) as z:
                    member = z.namelist()[0]; content = z.read(member)
                path = args.input_root.rstrip("/") + "/" + member; paths.append(path)
                result = await call("hdfs_sha256", {"path": path})
                require(result["sha256"] == hashlib.sha256(content).hexdigest() and result["bytes"] == len(content), "Hash mismatch")
            result = await call("hdfs_read_lines", {"path": paths[2], "start_line": 121, "limit": 1})
            row = json.loads(result["lines"][0]["text"])
            require(result["lines"][0]["line"] == 121 and row["orig_bytes"] == 50085 and result["next_line"] == 122, "Line pagination mismatch")
            dns = await call("hdfs_query_records", {"path": paths[1], "format": "jsonl", "group_by": ["id.orig_h", "query"], "time_field": "ts"})
            require(dns["matched_records"] == 120 and dns["groups"][0]["time"]["mean_interval_seconds"] == 60 and dns["groups"][0]["time"]["interval_count"] == 119, "DNS mismatch")
            outbound = await call("hdfs_query_records", {"path": paths[2], "format": "jsonl", "filters": {"id.orig_h": ["10.70.0.66"], "id.resp_h": ["203.0.113.66"]}, "sum_fields": ["orig_bytes", "resp_bytes"], "time_field": "ts"})
            require(outbound["matched_records"] == 120 and outbound["groups"][0]["sums"] == {"orig_bytes": 6010330, "resp_bytes": 240}, "Outbound mismatch")
            lateral = await call("hdfs_query_records", {"path": paths[2], "format": "jsonl", "filters": {"id.orig_h": ["10.70.0.66"], "id.resp_p": ["22", "445", "3389"]}, "distinct_fields": ["id.resp_h", "id.resp_p"], "time_field": "ts"})
            require(lateral["matched_records"] == 25 and lateral["groups"][0]["distinct"]["id.resp_h"]["count"] == 25 and lateral["groups"][0]["time"]["span_seconds"] == 240, "Lateral mismatch")
            nf = await call("hdfs_query_records", {"path": paths[3], "format": "jsonl", "filters": {"source_ip": ["10.70.0.66"], "destination_ip": ["203.0.113.66"]}, "sum_fields": ["bytes"]})
            require(nf["matched_records"] == 120 and nf["groups"][0]["sums"]["bytes"] == 6010330, "NetFlow mismatch")
            ids = await call("hdfs_query_records", {"path": paths[4], "format": "jsonl", "group_by": ["signature_id"]})
            require({g["keys"]["signature_id"]: g["count"] for g in ids["groups"]} == {"1300101": 120, "1300102": 120, "1300103": 100}, "IDS mismatch")
            fw = await call("hdfs_query_records", {"path": paths[5], "format": "kv", "filters": {"srcip": ["10.70.0.66"]}, "group_by": ["policyname", "simulation"]})
            require(fw["matched_records"] == 265 and all(g["keys"]["simulation"] == "true" for g in fw["groups"]), "Firewall mismatch")
            packets = await call("hdfs_pcap_packets", {"path": paths[0], "display_filter": "frame.number == 244 || frame.number == 1084", "limit": 2})
            require(packets["matching_packets"] == 2 and packets["packets"][0]["payload_text"].startswith("POST /upload/0 HTTP/1.0") and packets["packets"][1]["payload_text"] == "LAB13 coherent remote service probe", "Packet bytes mismatch")
            require(packets["source_sha256"] == audit["checks"][0]["result"]["sha256"], "Packet parent hash mismatch")
            audit["status"] = "PASS"
            audit["finished_at"] = datetime.now(timezone.utc).isoformat()
            args.output.write_text(json.dumps(audit, ensure_ascii=False, indent=2) + "\n")
            print(f"PASS: {len(audit['checks'])} real MCP calls verified; no model invoked")


def fail(message):
    raise AssertionError(message)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--endpoint", default="http://127.0.0.1:8001/mcp")
    p.add_argument("--input-root", default="/student/agentic-siem/incident-lab/input")
    p.add_argument("--samples", type=Path, default=Path(__file__).resolve().parents[1] / "sample-data")
    p.add_argument("--output", required=True, type=Path)
    asyncio.run(run(p.parse_args()))
