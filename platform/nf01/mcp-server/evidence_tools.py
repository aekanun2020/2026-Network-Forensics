"""Read-only DFIR tools over real HDFS files; bounded output, no case-specific rules."""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import math
import re
import shlex
import statistics
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import httpx
from mcp.server.fastmcp.exceptions import ToolError

MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ToolError(message)


def stamp(value):
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value)
    try:
        return float(text)
    except ValueError:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        require(dt.tzinfo is not None, "Timestamp needs an explicit timezone")
        return dt.timestamp()


def utc(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def bounded(result):
    require(len(json.dumps(result, ensure_ascii=False).encode()) <= MAX_RESPONSE_BYTES,
            "Result exceeds output budget; reduce groups, samples or selected fields")
    return result


def register_evidence_tools(mcp, hdfs_stat, safe_hdfs_path, hdfs_ui, fingerprint):
    semaphore = asyncio.Semaphore(2)

    def url(path):
        return f"{hdfs_ui}/webhdfs/v1{quote(safe_hdfs_path(path), safe='/')}"

    async def before(path):
        status = await hdfs_stat(path)
        require(status["type"] == "FILE", "Expected an HDFS file")
        require(status["length"] <= MAX_FILE_BYTES, "File exceeds 512 MiB examination limit")
        return status

    async def unchanged(path, prior):
        after = await hdfs_stat(path)
        require(all(after.get(k) == prior.get(k) for k in ("fileId", "length", "modificationTime")),
                "Source changed during examination; discard this result")

    async def chunks(path):
        async with httpx.AsyncClient(follow_redirects=True, timeout=120) as client:
            async with client.stream("GET", url(path), params={"op": "OPEN", "user.name": "spark"}) as response:
                response.raise_for_status()
                async for chunk in response.aiter_bytes(256 * 1024):
                    yield chunk

    async def lines(path, digest):
        pending = b""
        async for chunk in chunks(path):
            digest.update(chunk)
            pending += chunk
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                require(len(line) <= MAX_LINE_BYTES, "Record exceeds 1 MiB limit")
                yield line.rstrip(b"\r").decode("utf-8", errors="strict")
            require(len(pending) <= MAX_LINE_BYTES, "Record exceeds 1 MiB limit")
        if pending:
            yield pending.rstrip(b"\r").decode("utf-8", errors="strict")

    @mcp.tool()
    async def hdfs_sha256(path: str) -> dict:
        """Stream the whole real HDFS file (text or binary) and return its SHA-256. Virtual path omits /mcp."""
        async with semaphore:
            prior = await before(path)
            result = await fingerprint(safe_hdfs_path(path))
            await unchanged(path, prior)
            require(result["bytes"] == prior["length"], "Read length mismatch")
            return {"path": path, "physical_path": safe_hdfs_path(path), **result, "complete": True}

    @mcp.tool()
    async def hdfs_read_lines(path: str, start_line: int = 1, limit: int = 20) -> dict:
        """Read numbered UTF-8 records without loading a large log into model context. Lines are one-based; returns next_line."""
        require(start_line >= 1 and 1 <= limit <= 200, "start_line >= 1; limit 1..200")
        async with semaphore:
            prior = await before(path)
            selected, number, extra = [], 0, False
            digest = hashlib.sha256()
            stream = lines(path, digest)
            try:
                async for number, text in _enumerate(stream):
                    if number < start_line:
                        continue
                    if len(selected) == limit:
                        extra = True
                        break
                    selected.append({"line": number, "text": text})
            finally:
                await stream.aclose()
            await unchanged(path, prior)
            return bounded({"path": path, "file_bytes": prior["length"], "lines": selected,
                            "next_line": start_line + len(selected) if extra else None,
                            "reached_eof": not extra, "line_numbers_are_one_based": True})

    @mcp.tool()
    async def hdfs_query_records(
        path: str, format: str, filters: dict[str, list[str]] | None = None,
        group_by: list[str] | None = None, sum_fields: list[str] | None = None,
        distinct_fields: list[str] | None = None, time_field: str | None = None,
        sample_fields: list[str] | None = None, samples_per_group: int = 2,
        max_groups: int = 30, cidr_filters: dict[str, str] | None = None,
    ) -> dict:
        """Scan an entire JSONL or key=value log. Exact filters are AND across fields, OR within each list (values compared as strings). Field names are literal, including dots. Return counts, sums, distinct counts, UTC time/interval statistics and original line references. No attack labels or hidden detection rules. Missing requested fields fail rather than becoming zero. time_field must contain epoch seconds or timezone-aware ISO text; omit for split date/time fields."""
        require(format in {"jsonl", "kv"}, "format must be jsonl or kv")
        filters, group_by = filters or {}, group_by or []
        networks = {k: ipaddress.ip_network(v, strict=True) for k, v in (cidr_filters or {}).items()}
        sum_fields, distinct_fields = sum_fields or [], distinct_fields or []
        sample_fields = sample_fields or []
        require(0 <= samples_per_group <= 5 and 1 <= max_groups <= 100, "samples 0..5, max_groups 1..100")
        require(all(isinstance(v, list) and v and all(isinstance(x, str) for x in v) for v in filters.values()),
                "Each filter requires a nonempty list of strings")
        require(len(group_by) <= 5 and len(sum_fields) <= 8 and len(distinct_fields) <= 8,
                "Too many aggregation fields")
        async with semaphore:
            prior, digest = await before(path), hashlib.sha256()
            groups, total, matched = {}, 0, 0
            async for number, text in _enumerate(lines(path, digest)):
                total += 1
                try:
                    if format == "jsonl":
                        row = json.loads(text)
                    else:
                        parts = shlex.split(text)
                        require(all("=" in p for p in parts), f"Invalid key=value record at line {number}")
                        pairs = [p.split("=", 1) for p in parts]
                        require(len({k for k, _ in pairs}) == len(pairs), f"Duplicate field at line {number}")
                        row = dict(pairs)
                    require(isinstance(row, dict), f"Record {number} is not an object")
                    for field in [*filters, *networks]:
                        require(field in row, f"Missing filter field {field} at line {number}")
                    if not all(str(row[k]) in allowed for k, allowed in filters.items()) or not all(ipaddress.ip_address(row[k]) in net for k, net in networks.items()):
                        continue
                    for field in [*group_by, *sum_fields, *distinct_fields, *sample_fields, *([time_field] if time_field else [])]:
                        require(field in row, f"Missing field {field} at line {number}")
                    matched += 1
                    key = tuple(str(row[k]) for k in group_by)
                    if key not in groups:
                        require(len(groups) < 10000, "More than 10,000 groups; refine filters/group_by")
                        groups[key] = {"keys": dict(zip(group_by, key)), "count": 0,
                                       "sums": dict.fromkeys(sum_fields, 0),
                                       "distinct": {f: set() for f in distinct_fields},
                                       "times": [], "samples": []}
                    g = groups[key]; g["count"] += 1
                    for field in sum_fields:
                        value = row[field]
                        require(not isinstance(value, bool), f"Boolean sum field {field}")
                        number_value = int(value) if isinstance(value, int) or re.fullmatch(r"[+-]?\d+", str(value)) else float(value)
                        require(math.isfinite(number_value), "Non-finite numeric value")
                        g["sums"][field] += number_value
                    for field in distinct_fields:
                        g["distinct"][field].add(json.dumps(row[field], sort_keys=True, ensure_ascii=False))
                    if time_field:
                        g["times"].append(stamp(row[time_field]))
                    if len(g["samples"]) < samples_per_group:
                        g["samples"].append({"line": number, "record": {f: row[f] for f in sample_fields} if sample_fields else row})
                except (ValueError, TypeError, OverflowError) as exc:
                    raise ToolError(f"Invalid record at line {number}: {exc}") from exc
            await unchanged(path, prior)
            output = []
            for _, g in sorted(groups.items(), key=lambda pair: (-pair[1]["count"], pair[0]))[:max_groups]:
                g["distinct"] = {f: {"count": len(v), "examples": [json.loads(x) for x in sorted(v)[:30]],
                                      "examples_truncated": len(v) > 30} for f, v in g["distinct"].items()}
                times = sorted(g.pop("times"))
                if times:
                    intervals = [b-a for a, b in zip(times, times[1:])]
                    g["time"] = {"field": time_field, "first_utc": utc(times[0]), "last_utc": utc(times[-1]),
                                 "span_seconds": times[-1]-times[0], "interval_count": len(intervals),
                                 "mean_interval_seconds": statistics.mean(intervals) if intervals else None,
                                 "population_stddev_seconds": statistics.pstdev(intervals) if intervals else None}
                output.append(g)
            return bounded({"path": path, "file_bytes": prior["length"], "source_sha256": digest.hexdigest(),
                            "scanned_records": total, "matched_records": matched, "filters": filters,
                            "cidr_filters": cidr_filters or {}, "group_count": len(groups), "groups_truncated": len(groups) > max_groups,
                            "groups": output, "complete_scan": True,
                            "interpretation": "Computed record statistics only; no incident verdict"})

    @mcp.tool()
    async def hdfs_correlate_records(
        left_path: str, right_path: str, left_format: str, right_format: str,
        left_keys: list[str], right_keys: list[str],
        left_time_fields: list[str], right_time_fields: list[str],
        left_filters: dict[str, list[str]] | None = None,
        right_filters: dict[str, list[str]] | None = None,
        max_delta_seconds: float = 1.0, naive_timezone: str | None = None,
        max_examples: int = 3, left_group_by: list[str] | None = None,
    ) -> dict:
        """Join two real HDFS log views by equal keys AND timestamp tolerance. Use UID/parentuid or a full directional tuple (source/dest IP, source/dest port, protocol). Literal field names. Time fields: one epoch/ISO field, or two date/time fields; timezone-less input requires explicit naive_timezone='UTC'. Return full-source hashes, line-numbered pairs, deltas, unmatched counts and one-to-many cardinality. Counts are records/pairs, not automatically sessions. Optional left_group_by returns exact matched cohort counts and first/last left timestamps (up to 100 groups). No attack verdict."""
        require(left_path != right_path, "Choose two different views")
        require(len(left_keys) == len(right_keys) and 1 <= len(left_keys) <= 5, "Equal key lists of length 1..5 required")
        require(0 <= max_delta_seconds <= 60 and 1 <= max_examples <= 5, "delta 0..60 seconds, examples 1..5")
        require(naive_timezone in {None, "UTC"}, "Explicit UTC is the only supported naive timezone")
        async def scan(path, fmt, keys, time_fields, filters):
            require(fmt in {"jsonl", "kv"} and 1 <= len(time_fields) <= 2, "format jsonl/kv and 1..2 time fields required")
            filters = filters or {}
            require(all(isinstance(v, list) and v and all(isinstance(x, str) for x in v) for v in filters.values()), "Filters require string lists")
            prior, digest, rows, total = await before(path), hashlib.sha256(), [], 0
            async for number, text in _enumerate(lines(path, digest)):
                total += 1
                if fmt == "jsonl":
                    row = json.loads(text)
                else:
                    pairs = [v.split("=", 1) for v in shlex.split(text)]
                    require(all(len(v) == 2 for v in pairs) and len({v[0] for v in pairs}) == len(pairs), f"Invalid key=value at {number}")
                    row = dict(pairs)
                require(isinstance(row, dict), f"Nonobject at {number}")
                require(all(k in row for k in filters), f"Missing filter field at {number}")
                if not all(str(row[k]) in v for k, v in filters.items()):
                    continue
                require(all(k in row for k in keys + time_fields), f"Missing join/time field at {number}")
                raw_time = row[time_fields[0]] if len(time_fields) == 1 else "T".join(str(row[k]) for k in time_fields)
                try:
                    timestamp = stamp(raw_time)
                except ToolError:
                    require(naive_timezone == "UTC", "Timezone-less join time requires explicit naive_timezone=UTC")
                    timestamp = datetime.fromisoformat(str(raw_time)).replace(tzinfo=timezone.utc).timestamp()
                require(math.isfinite(timestamp), "Nonfinite timestamp")
                require(len(rows) < 200000, "Filtered view exceeds 200000 records; refine filters")
                rows.append({"line": number, "record": row, "time": timestamp, "key": tuple(str(row[k]) for k in keys)})
            await unchanged(path, prior)
            return rows, {"path": path, "sha256": digest.hexdigest(), "scanned_records": total, "filtered_records": len(rows)}
        require(len(left_group_by or []) <= 4, "At most four left cohort fields")
        async with semaphore:
            left, left_meta = await scan(left_path, left_format, left_keys, left_time_fields, left_filters)
            right, right_meta = await scan(right_path, right_format, right_keys, right_time_fields, right_filters)
            index = defaultdict(list)
            for r in right:
                index[r["key"]].append(r)
            matched_left, matched_right, pairs, multi, examples, deltas = set(), set(), 0, 0, [], []
            cohorts = {}
            for l in left:
                require(all(k in l["record"] for k in (left_group_by or [])), "Missing left cohort field")
                hits, right_lines = 0, set()
                for r in index[l["key"]]:
                    delta = r["time"] - l["time"]
                    if abs(delta) > max_delta_seconds:
                        continue
                    hits += 1; pairs += 1; right_lines.add(r["line"])
                    require(pairs <= 1000000, "Join exceeds 1 million pairs; refine keys/time")
                    matched_left.add(l["line"]); matched_right.add(r["line"]); deltas.append(delta)
                    if len(examples) < max_examples:
                        examples.append({"left": {"line": l["line"], "record": l["record"]},
                                         "right": {"line": r["line"], "record": r["record"]}, "time_delta_seconds": delta})
                multi += hits > 1
                if hits and left_group_by:
                    key = tuple(str(l["record"][k]) for k in left_group_by)
                    require(key in cohorts or len(cohorts) < 100, "More than 100 matched cohorts; refine filters")
                    c = cohorts.setdefault(key, {"keys": dict(zip(left_group_by,key)), "matched_left_records": 0, "right_lines": set(), "matched_pairs": 0, "first_ts": l["time"], "last_ts": l["time"]})
                    c["matched_left_records"] += 1; c["right_lines"].update(right_lines); c["matched_pairs"] += hits
                    c["first_ts"] = min(c["first_ts"],l["time"]); c["last_ts"] = max(c["last_ts"],l["time"])
            for c in cohorts.values():
                c["matched_right_records"] = len(c.pop("right_lines"))
            return bounded({"left": left_meta, "right": right_meta, "left_keys": left_keys, "right_keys": right_keys,
                "matched_pairs": pairs, "matched_left_records": len(matched_left), "matched_right_records": len(matched_right),
                "unmatched_left_records": len(left)-len(matched_left), "unmatched_right_records": len(right)-len(matched_right),
                "left_records_with_multiple_matches": multi, "max_delta_seconds": max_delta_seconds,
                "observed_delta_min_seconds": min(deltas) if deltas else None, "observed_delta_max_seconds": max(deltas) if deltas else None,
                "examples": examples, "matched_cohorts": list(cohorts.values()), "complete_scan": True,
                "interpretation": "Equal-key/time matches between views; shared origin is not independent corroboration"})

    @mcp.tool()
    async def hdfs_pcap_packets(path: str, display_filter: str, limit: int = 10, payload_bytes: int = 160) -> dict:
        """Inspect a real HDFS PCAP using TShark/Wireshark display-filter syntax. Scans the capture and returns matching packet count plus bounded numbered packet evidence and TCP payload hex/text. Use numeric addresses; name resolution is disabled. Packet count is not connection count. Requires tshark installed in the MCP image."""
        require(1 <= limit <= 50 and 0 <= payload_bytes <= 512, "limit 1..50; payload_bytes 0..512")
        require(0 < len(display_filter) <= 512, "A nonempty display filter up to 512 characters is required")
        async with semaphore:
            prior = await before(path)
            digest = hashlib.sha256()
            with tempfile.TemporaryDirectory(prefix="dfir-pcap-") as directory:
                capture = Path(directory) / "evidence.pcap"
                with capture.open("wb") as f:
                    async for chunk in chunks(path):
                        f.write(chunk); digest.update(chunk)
                await unchanged(path, prior)
                require(capture.stat().st_size == prior["length"], "Capture read length mismatch")
                fields = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
                          "udp.srcport", "udp.dstport", "tcp.len", "tcp.payload", "dns.qry.name", "dns.a", "_ws.col.Protocol", "tls.record.content_type", "tls.handshake.type"]
                command = ["tshark", "-n", "-r", str(capture), "-Y", display_filter, "-T", "fields", "-E", "occurrence=f"]
                for field in fields:
                    command += ["-e", field]
                try:
                    proc = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE,
                                                               stderr=asyncio.subprocess.PIPE, limit=2*1024*1024)
                except FileNotFoundError as exc:
                    raise ToolError("tshark is missing from the actual MCP image") from exc
                error_task = asyncio.create_task(proc.stderr.read())
                count, packets = 0, []
                async def collect():
                    nonlocal count
                    async for raw in proc.stdout:
                        count += 1
                        if len(packets) >= limit:
                            continue
                        values = raw.decode().rstrip("\r\n").split("\t")
                        require(len(values) == len(fields), "Unexpected TShark field output")
                        row = dict(zip(fields, values))
                        payload = bytes.fromhex(row.pop("tcp.payload").replace(":", ""))
                        row.update(packet_number=int(row["frame.number"]), utc=utc(float(row["frame.time_epoch"])),
                                   payload_length=len(payload), payload_hex=payload[:payload_bytes].hex(),
                                   payload_text=payload[:payload_bytes].decode("utf-8", errors="backslashreplace"),
                                   payload_truncated=len(payload)>payload_bytes)
                        row["protocol_observation"] = ("http_plaintext_observed" if re.match(rb"(?:GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH) \S+ HTTP/1\.[01]\r\n|HTTP/1\.[01] \d{3}", payload) else "tls_record_observed" if row["tls.record.content_type"] else "not_established")
                        packets.append(row)
                    await proc.wait()
                    error = await error_task
                    require(proc.returncode == 0, "TShark failed: " + error.decode(errors="replace")[-2000:])
                try:
                    await asyncio.wait_for(collect(), timeout=120)
                finally:
                    if proc.returncode is None:
                        proc.kill(); await proc.wait()
                    if not error_task.done():
                        error_task.cancel()
                return bounded({"path": path, "file_bytes": prior["length"], "source_sha256": digest.hexdigest(),
                                "display_filter": display_filter, "matching_packets": count, "packets": packets,
                                "samples_truncated": count > limit, "complete_scan": True,
                                "dissector": "tshark", "interpretation": "Observed packets only; no compromise verdict"})


async def _enumerate(iterator):
    number = 0
    async for item in iterator:
        number += 1
        yield number, item
