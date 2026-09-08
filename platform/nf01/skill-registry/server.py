"""Read-only security-log skill registry plus a safe draft workspace."""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from mcp.server.fastmcp import FastMCP


SKILLS_DIR = Path(os.environ.get("SKILLS_DIR", "/skills")).resolve()
DRAFTS_DIR = Path(os.environ.get("DRAFTS_DIR", "/drafts")).resolve()
NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*(?:\n|\Z)(.*)\Z", re.DOTALL)
MAX_SKILL_BYTES = 64 * 1024
MAX_PARSER_BYTES = 128 * 1024
MAX_RESOURCE_BYTES = 256 * 1024
MAX_SPARK_JOB_BYTES = 512 * 1024
MAX_SAMPLE_BYTES = 64 * 1024
MAX_TEST_SAMPLES = 100
ALLOWED_FORMATS = {"csv_syslog", "regex_syslog", "kv_syslog", "json_lines"}
ALLOWED_FRONTMATTER = {"name", "description"}
ALLOWED_VALUE_TYPES = {"string", "timestamp", "integer", "long", "lowercase", "ip", "boolean"}
RESOURCE_EXTENSIONS = {
    "references": {".csv", ".json", ".md", ".txt", ".yaml", ".yml"},
    "scripts": {".py", ".sh", ".sql"},
    "assets": {
        ".csv",
        ".json",
        ".log",
        ".md",
        ".py",
        ".sh",
        ".sql",
        ".template",
        ".tmpl",
        ".txt",
        ".yaml",
        ".yml",
    },
}
WORKFLOW_SKILL = "analyze-security-logs-with-spark"
SPARK_JOB_TEMPLATE = "assets/spark_security_report_job.py.tmpl"
SPARK_POLICY_RESOURCE = "references/pyspark-policy-v1.json"
REPORT_CONTRACT_RESOURCE = "references/report-contract-v1.json"
SYSTEM_WORKFLOW_SKILL = "analyze-system-logs-with-spark"
SYSTEM_SPARK_JOB_TEMPLATE = "assets/spark_system_event_report_job.py.tmpl"
SYSTEM_REPORT_CONTRACT_RESOURCE = "references/system-event-report-contract-v1.json"
DNS_WORKFLOW_SKILL = "analyze-dns-logs-with-spark"
DNS_SPARK_JOB_TEMPLATE = "assets/spark_dns_report_job.py.tmpl"
DNS_REPORT_CONTRACT_RESOURCE = "references/dns-report-contract-v1.json"
IDS_WORKFLOW_SKILL = "analyze-ids-alerts-with-spark"
IDS_SPARK_JOB_TEMPLATE = "assets/spark_ids_alert_report_job.py.tmpl"
IDS_REPORT_CONTRACT_RESOURCE = "references/ids-report-contract-v1.json"
C2_DNS_WORKFLOW_SKILL = "analyze-c2-dns-with-spark"
C2_DNS_SPARK_JOB_TEMPLATE = "assets/spark_c2_dns_detection_job.py.tmpl"
C2_DNS_REPORT_CONTRACT_RESOURCE = "references/c2-detection-report-contract-v1.json"
EXFIL_WORKFLOW_SKILL = "analyze-exfiltration-netflow-with-spark"
EXFIL_SPARK_JOB_TEMPLATE = "assets/spark_exfiltration_netflow_job.py.tmpl"
EXFIL_REPORT_CONTRACT_RESOURCE = "references/exfiltration-detection-report-contract-v1.json"
LATERAL_WORKFLOW_SKILL = "analyze-lateral-movement-with-spark"
LATERAL_SPARK_JOB_TEMPLATE = "assets/spark_lateral_movement_job.py.tmpl"
LATERAL_REPORT_CONTRACT_RESOURCE = "references/lateral-movement-detection-report-contract-v1.json"
CORRELATION_WORKFLOW_SKILL = "correlate-security-evidence-with-spark"
CORRELATION_SPARK_JOB_TEMPLATE = "assets/spark_security_correlation_job.py.tmpl"
CORRELATION_REPORT_CONTRACT_RESOURCE = "references/security-investigation-report-contract-v1.json"
PCAP_CORRELATION_SPARK_JOB_TEMPLATE = "assets/spark_pcap_security_correlation_job.py.tmpl"
PCAP_CORRELATION_REPORT_CONTRACT_RESOURCE = "references/security-investigation-report-contract-v2.json"
HANDOFF_WORKFLOW_SKILL = "build-security-investigation-handoff-with-spark"
HANDOFF_SPARK_JOB_TEMPLATE = "assets/spark_security_investigation_handoff_job.py.tmpl"
HANDOFF_REPORT_CONTRACT_RESOURCE = "references/security-investigation-handoff-contract-v1.json"
PCAP_HANDOFF_SPARK_JOB_TEMPLATE = "assets/spark_coherent_pcap_investigation_handoff_job.py.tmpl"
PCAP_HANDOFF_REPORT_CONTRACT_RESOURCE = "references/security-investigation-handoff-contract-v2.json"
REPORT_COUNT_TABLES = {
    "top_actions": 10,
    "top_applications": 10,
    "top_policies": 10,
    "top_source_zones": 10,
    "top_destination_zones": 10,
    "protocols": 10,
    "session_end_reasons": 20,
}
REPORT_TRAFFIC_TABLES = {
    "top_source_talkers": ("source_ip", 10, "bytes"),
    "top_destination_talkers": ("destination_ip", 10, "bytes"),
    "traffic_by_source_zone": ("source_zone", 10, "bytes"),
    "traffic_by_destination_zone": ("destination_zone", 10, "bytes"),
    "traffic_by_application": ("application", 10, "bytes"),
    "top_source_users": ("source_user", 20, "sessions"),
}
REPORT_REQUIRED_NONEMPTY_TABLES = set(REPORT_COUNT_TABLES) | (
    set(REPORT_TRAFFIC_TABLES) - {"top_source_users"}
)
REPORT_TABLE_SOURCE_FIELDS = {
    "top_actions": "event_action",
    "top_applications": "application",
    "top_policies": "policy_name",
    "top_source_zones": "source_zone",
    "top_destination_zones": "destination_zone",
    "protocols": "network_protocol",
    "session_end_reasons": "session_end_reason",
    **{name: spec[0] for name, spec in REPORT_TRAFFIC_TABLES.items()},
}

mcp = FastMCP(
    "security-log-skills",
    instructions=(
        "Discover approved vendor parsers and trusted security analytics workflows. "
        "Render and validate Spark jobs and reports without executing skill code. "
        "Published skills are read-only. Drafts can be saved for Git review, but this "
        "server never promotes drafts or executes code from a skill."
    ),
    host="0.0.0.0",
    port=8000,
)


def _safe_child(root: Path, name: str) -> Path:
    if not NAME_RE.fullmatch(name) or len(name) > 80:
        raise ValueError("name must be lowercase kebab-case and at most 80 characters")
    candidate = (root / name).resolve()
    if candidate.parent != root:
        raise ValueError("path escapes registry root")
    return candidate


def _read_limited(path: Path, limit: int) -> str:
    if not path.is_file():
        raise FileNotFoundError(str(path))
    if path.stat().st_size > limit:
        raise ValueError(f"{path.name} exceeds {limit} bytes")
    return path.read_text(encoding="utf-8")


def _safe_resource_path(skill_path: Path, resource_path: str) -> Path:
    """Resolve one allowlisted text resource without following an escaping symlink."""
    if not isinstance(resource_path, str) or not resource_path or len(resource_path) > 512:
        raise ValueError("resource_path must be a non-empty relative path")
    if "\\" in resource_path:
        raise ValueError("resource_path must use forward slashes")
    relative = Path(resource_path)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("resource_path must be a normalized relative path")
    category = relative.parts[0]
    if category not in RESOURCE_EXTENSIONS or len(relative.parts) < 2:
        raise ValueError("resource_path must be below references/, scripts/, or assets/")
    suffix = relative.suffix.lower()
    if suffix not in RESOURCE_EXTENSIONS[category]:
        raise ValueError(f"resource extension {suffix or '<none>'!r} is not readable")

    skill_root = skill_path.resolve()
    candidate = skill_root.joinpath(*relative.parts)
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError:
        raise FileNotFoundError(resource_path) from None
    try:
        resolved.relative_to(skill_root)
    except ValueError:
        raise ValueError("resource path escapes its skill directory") from None
    probe = candidate
    while probe != skill_root:
        if probe.is_symlink():
            raise ValueError("symbolic links are not exposed as skill resources")
        probe = probe.parent
    if not resolved.is_file():
        raise FileNotFoundError(resource_path)
    if resolved.stat().st_size > MAX_RESOURCE_BYTES:
        raise ValueError(f"resource exceeds {MAX_RESOURCE_BYTES} bytes")
    return resolved


def _resource_metadata(skill_path: Path, resource_path: str) -> dict[str, Any]:
    path = _safe_resource_path(skill_path, resource_path)
    data = path.read_bytes()
    return {
        "path": resource_path,
        "category": Path(resource_path).parts[0],
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _list_skill_resources(skill_path: Path) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for category in sorted(RESOURCE_EXTENSIONS):
        category_path = skill_path / category
        if not category_path.is_dir() or category_path.is_symlink():
            continue
        for directory, directory_names, file_names in os.walk(category_path, followlinks=False):
            directory_path = Path(directory)
            directory_names[:] = sorted(
                name for name in directory_names if not (directory_path / name).is_symlink()
            )
            for file_name in sorted(file_names):
                candidate = directory_path / file_name
                relative = candidate.relative_to(skill_path).as_posix()
                if candidate.suffix.lower() not in RESOURCE_EXTENSIONS[category]:
                    continue
                try:
                    resources.append(_resource_metadata(skill_path, relative))
                except (OSError, ValueError):
                    continue
    return sorted(resources, key=lambda item: item["path"])


def _parse_skill_markdown(text: str, expected_name: str | None = None) -> dict[str, Any]:
    match = FRONTMATTER_RE.match(text)
    if not match:
        raise ValueError("SKILL.md must start with YAML frontmatter")
    metadata = yaml.safe_load(match.group(1))
    if not isinstance(metadata, dict):
        raise ValueError("skill frontmatter must be a mapping")
    unknown = set(metadata) - ALLOWED_FRONTMATTER
    missing = ALLOWED_FRONTMATTER - set(metadata)
    if unknown:
        raise ValueError(f"unsupported frontmatter keys: {sorted(unknown)}")
    if missing:
        raise ValueError(f"missing frontmatter keys: {sorted(missing)}")
    name = metadata.get("name")
    description = metadata.get("description")
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise ValueError("frontmatter name must be lowercase kebab-case")
    if expected_name and name != expected_name:
        raise ValueError("frontmatter name must match its directory")
    if not isinstance(description, str) or not description.strip():
        raise ValueError("frontmatter description must be non-empty")
    if len(description) > 1024:
        raise ValueError("frontmatter description is too long")
    body = match.group(2).strip()
    if not body:
        raise ValueError("skill body must be non-empty")
    return {"name": name, "description": description.strip(), "body": body}


def _validate_parser(config: Any, expected_skill: str | None = None) -> list[str]:
    errors: list[str] = []
    if not isinstance(config, dict):
        return ["parser YAML must be a mapping"]
    required = {"id", "version", "status", "skill", "vendor", "product", "log_type", "format", "detection", "parse", "mapping", "defaults"}
    for key in sorted(required - set(config)):
        errors.append(f"missing parser key: {key}")
    if config.get("format") not in ALLOWED_FORMATS:
        errors.append(f"format must be one of {sorted(ALLOWED_FORMATS)}")
    if config.get("status") not in {"approved", "draft"}:
        errors.append("status must be approved or draft")
    for key in ("id", "version", "skill", "vendor", "product", "log_type"):
        if not isinstance(config.get(key), str) or not config.get(key).strip():
            errors.append(f"{key} must be a non-empty string")
    if expected_skill and config.get("skill") != expected_skill:
        errors.append("parser skill must match its containing skill")
    if not isinstance(config.get("mapping"), dict) or not config.get("mapping"):
        errors.append("mapping must be a non-empty mapping")
    else:
        for source, target in config["mapping"].items():
            if not isinstance(target, dict) or not isinstance(target.get("field"), str):
                errors.append(f"mapping {source!r} must define a string field")
                continue
            if target.get("type", "string") not in ALLOWED_VALUE_TYPES:
                errors.append(f"mapping {source!r} has unsupported type")
    detection = config.get("detection")
    if not isinstance(detection, dict):
        errors.append("detection must be a mapping")
    elif not isinstance(detection.get("required_tokens", []), list):
        errors.append("detection.required_tokens must be a list")
    parse = config.get("parse")
    if not isinstance(parse, dict):
        errors.append("parse must be a mapping")
    elif config.get("format") == "regex_syslog":
        try:
            re.compile(str(parse.get("pattern", "")))
        except re.error as exc:
            errors.append(f"invalid parse.pattern: {exc}")
    elif config.get("format") == "csv_syslog":
        index_base = parse.get("index_base")
        if not isinstance(index_base, int) or isinstance(index_base, bool) or index_base != 0:
            errors.append("csv parse.index_base must be integer 0")
        try:
            re.compile(str(parse.get("payload_start_pattern", "")))
        except re.error as exc:
            errors.append(f"invalid payload_start_pattern: {exc}")
        mapping = config.get("mapping")
        if isinstance(mapping, dict):
            for source in mapping:
                if isinstance(source, bool) or not re.fullmatch(r"\d+", str(source)):
                    errors.append(f"CSV mapping source {source!r} must be a non-negative integer index")
        if isinstance(detection, dict) and isinstance(detection.get("discriminator"), dict):
            discriminator_index = detection["discriminator"].get("field_index")
            if (
                isinstance(discriminator_index, bool)
                or not re.fullmatch(r"\d+", str(discriminator_index))
            ):
                errors.append("detection.discriminator.field_index must be a non-negative integer index")
    elif config.get("format") == "kv_syslog":
        timestamp = parse.get("timestamp")
        key_pattern = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*$")
        if not isinstance(timestamp, dict):
            errors.append("kv parse.timestamp must be a mapping")
        else:
            sources = timestamp.get("sources")
            if (
                not isinstance(sources, list)
                or not 1 <= len(sources) <= 3
                or not all(isinstance(item, str) and key_pattern.fullmatch(item) for item in sources)
            ):
                errors.append("kv parse.timestamp.sources must contain 1-3 safe key names")
            if timestamp.get("target", "event_time") != "event_time":
                errors.append("kv parse.timestamp.target must be event_time")
            if not isinstance(timestamp.get("format"), str) or not timestamp.get("format"):
                errors.append("kv parse.timestamp.format must be non-empty")
        mapping = config.get("mapping")
        if isinstance(mapping, dict):
            for source in mapping:
                if not isinstance(source, str) or not key_pattern.fullmatch(source):
                    errors.append(f"KV mapping source {source!r} must be a safe key name")
    elif config.get("format") == "json_lines":
        key_pattern = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*$")
        timestamp = parse.get("timestamp")
        if not isinstance(timestamp, dict): errors.append("json_lines parse.timestamp must be a mapping")
        else:
            if not isinstance(timestamp.get("source"), str) or not key_pattern.fullmatch(timestamp.get("source", "")): errors.append("json_lines parse.timestamp.source must be a safe JSON key")
            if timestamp.get("format") != "epoch_seconds": errors.append("json_lines parse.timestamp.format must be epoch_seconds")
            if timestamp.get("target", "event_time") != "event_time": errors.append("json_lines parse.timestamp.target must be event_time")
        if isinstance(config.get("mapping"), dict):
            for source in config["mapping"]:
                if not isinstance(source, str) or not key_pattern.fullmatch(source): errors.append(f"JSON mapping source {source!r} must be a safe key")
    return errors


def _load_parser(path: Path, expected_skill: str | None = None) -> dict[str, Any]:
    text = _read_limited(path, MAX_PARSER_BYTES)
    config = yaml.safe_load(text)
    errors = _validate_parser(config, expected_skill)
    if errors:
        raise ValueError("; ".join(errors))
    config["_path"] = str(path)
    return config


def _skill_dirs() -> list[Path]:
    if not SKILLS_DIR.is_dir():
        return []
    return sorted(
        path
        for path in SKILLS_DIR.iterdir()
        if path.is_dir() and not path.is_symlink() and NAME_RE.fullmatch(path.name)
    )


def _load_skill(path: Path) -> dict[str, Any]:
    parsed = _parse_skill_markdown(_read_limited(path / "SKILL.md", MAX_SKILL_BYTES), path.name)
    parser_paths = sorted((path / "assets" / "parsers").glob("*.yaml")) if (path / "assets" / "parsers").is_dir() else []
    safe_parser_paths = [
        _safe_resource_path(path, parser_path.relative_to(path).as_posix())
        for parser_path in parser_paths
    ]
    parsed["parsers"] = [_load_parser(parser_path, path.name) for parser_path in safe_parser_paths]
    for parser in parsed["parsers"]:
        if parser["status"] != "approved":
            raise ValueError(f"published parser {parser['id']} must have approved status")
    parsed["kind"] = "parser" if parsed["parsers"] else "workflow"
    parsed["resources"] = _list_skill_resources(path)
    return parsed


def _all_parsers() -> list[dict[str, Any]]:
    parsers: list[dict[str, Any]] = []
    for skill_dir in _skill_dirs():
        try:
            parsers.extend(_load_skill(skill_dir)["parsers"])
        except (OSError, ValueError, yaml.YAMLError):
            continue
    return parsers


def _cast(value: Any, value_type: str) -> Any:
    if value_type == "boolean":
        if isinstance(value, bool): return value
        if str(value).strip().lower() in {"true", "1"}: return True
        if str(value).strip().lower() in {"false", "0"}: return False
        raise ValueError(f"invalid boolean value: {value!r}")
    value = str(value).strip()
    if value == "":
        return None
    if value_type in {"integer", "long"}:
        return int(value)
    if value_type == "lowercase":
        return value.lower()
    if value_type == "ip":
        ipaddress.ip_address(value)
        return value
    return value


def _put_field(record: dict[str, Any], field: str, value: Any) -> None:
    if field.startswith("vendor_fields."):
        record.setdefault("vendor_fields", {})[field.split(".", 1)[1]] = value
    else:
        record[field] = value


def _parse_record(config: dict[str, Any], raw_event: str) -> dict[str, Any]:
    if len(raw_event.encode("utf-8")) > MAX_SAMPLE_BYTES:
        raise ValueError("sample exceeds size limit")
    record: dict[str, Any] = dict(config.get("defaults", {}))
    record.update(
        raw_event=raw_event,
        ingest_time=datetime.now(timezone.utc).isoformat(),
        parser_id=config["id"],
        parser_version=str(config["version"]),
        parse_status="parsed",
    )
    required_tokens = config.get("detection", {}).get("required_tokens", [])
    if any(str(token) not in raw_event for token in required_tokens):
        raise ValueError("required content fingerprint did not match")

    if config["format"] == "csv_syslog":
        start = re.search(config["parse"]["payload_start_pattern"], raw_event)
        if not start:
            raise ValueError("CSV payload start was not found")
        payload = raw_event[start.start():]
        fields = next(csv.reader(io.StringIO(payload), delimiter=config["parse"].get("delimiter", ","), quotechar=config["parse"].get("quotechar", '"')))
        minimum = int(config["detection"].get("min_fields", 0))
        if len(fields) < minimum:
            raise ValueError(f"record has {len(fields)} fields; parser requires {minimum}")
        discriminator = config["detection"].get("discriminator")
        if discriminator:
            index = int(discriminator["field_index"])
            if index >= len(fields) or fields[index] not in discriminator["accepted_values"]:
                raise ValueError("CSV discriminator did not match")
        for source, target in config["mapping"].items():
            index = int(source)
            if index >= len(fields):
                continue
            _put_field(record, target["field"], _cast(fields[index], target.get("type", "string")))
        mapped = {int(index) for index in config["mapping"]}
        extras = {str(index): value for index, value in enumerate(fields) if index not in mapped and value != ""}
        if extras:
            record.setdefault("vendor_fields", {})["unmapped_columns"] = extras
    elif config["format"] == "regex_syslog":
        match = re.fullmatch(config["parse"]["pattern"], raw_event)
        if not match:
            raise ValueError("regex parser did not match")
        groups = match.groupdict()
        for source, target in config["mapping"].items():
            if groups.get(str(source)) is not None:
                _put_field(record, target["field"], _cast(groups[str(source)], target.get("type", "string")))
    elif config["format"] == "kv_syslog":
        pairs: dict[str, str] = {}
        for token in shlex.split(raw_event):
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            pairs[key] = value
        for source, target in config["mapping"].items():
            if source in pairs:
                _put_field(
                    record,
                    target["field"],
                    _cast(pairs[source], target.get("type", "string")),
                )
        timestamp = config["parse"]["timestamp"]
        timestamp_values = [pairs.get(source, "") for source in timestamp["sources"]]
        if all(timestamp_values):
            record[timestamp.get("target", "event_time")] = timestamp.get(
                "separator", " "
            ).join(timestamp_values)
    else:
        try: payload = json.loads(raw_event)
        except json.JSONDecodeError as exc: raise ValueError(f"invalid JSON record: {exc}") from None
        if not isinstance(payload, dict): raise ValueError("JSON record must be an object")
        for source, target in config["mapping"].items():
            if source in payload and payload[source] is not None: _put_field(record,target["field"],_cast(payload[source],target.get("type","string")))
        timestamp=config["parse"]["timestamp"]; timestamp_value=payload.get(timestamp["source"])
        if timestamp_value is not None:
            try: record[timestamp.get("target","event_time")]=datetime.fromtimestamp(float(timestamp_value),tz=timezone.utc).isoformat()
            except (TypeError,ValueError,OverflowError): raise ValueError("invalid epoch_seconds timestamp") from None

    missing = [field for field in config.get("validation", {}).get("required_output", []) if record.get(field) in {None, ""}]
    if missing:
        record["parse_status"] = "partial"
        record["parse_warnings"] = [f"missing required output: {field}" for field in missing]
    return record


def _resolve(sample: str, vendor: str | None, product: str | None, log_type: str | None) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for parser in _all_parsers():
        if parser.get("status") != "approved":
            continue
        score = 0
        reasons: list[str] = []
        for supplied, key, points in ((vendor, "vendor", 30), (product, "product", 20), (log_type, "log_type", 15)):
            if supplied and supplied.lower() == str(parser.get(key, "")).lower():
                score += points
                reasons.append(f"{key} matched")
            elif supplied:
                score -= points
        tokens = parser.get("detection", {}).get("required_tokens", [])
        hits = sum(1 for token in tokens if str(token) in sample)
        score += hits * 10
        if hits:
            reasons.append(f"{hits} content fingerprint(s) matched")
        try:
            _parse_record(parser, sample)
            score += 40
            reasons.append("deterministic parser accepted sample")
            parse_success = True
        except (ValueError, TypeError, csv.Error):
            parse_success = False
        if score > 0:
            candidates.append(
                {
                    "parser_id": parser["id"],
                    "skill": parser["skill"],
                    "vendor": parser["vendor"],
                    "product": parser["product"],
                    "log_type": parser["log_type"],
                    "score": score,
                    "confidence": min(max(score, 0), 100) / 100,
                    "parse_success": parse_success,
                    "reasons": reasons,
                }
            )
    return sorted(candidates, key=lambda item: (item["score"], item["parser_id"]), reverse=True)


def _parser_by_id(skill_name: str, parser_id: str) -> dict[str, Any]:
    skill = _load_skill(_safe_child(SKILLS_DIR, skill_name))
    for parser in skill["parsers"]:
        if parser["id"] == parser_id:
            return parser
    raise ValueError(f"parser {parser_id!r} not found in {skill_name!r}")


def _published_resource(skill_name: str, resource_path: str) -> tuple[Path, str]:
    skill_path = _safe_child(SKILLS_DIR, skill_name)
    path = _safe_resource_path(skill_path, resource_path)
    return path, _read_limited(path, MAX_RESOURCE_BYTES)


def _published_json_resource(skill_name: str, resource_path: str) -> dict[str, Any]:
    _, text = _published_resource(skill_name, resource_path)
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid published JSON resource {resource_path}: {exc}") from None
    if not isinstance(value, dict):
        raise ValueError(f"published JSON resource {resource_path} must be an object")
    return value


def _public_parser(parser: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in parser.items() if key != "_path"}


def _spark_template_parser_errors(parser: dict[str, Any]) -> list[str]:
    """Return incompatibilities with the trusted security-report template."""
    errors: list[str] = []
    parser_format = parser.get("format")
    is_system = parser.get("log_type") == "system"
    is_dns = parser.get("log_type") == "dns"
    is_ids = parser.get("log_type") == "ids"
    is_c2_dns = parser.get("log_type") == "c2_dns"
    is_exfil = parser.get("log_type") == "exfil_netflow"
    is_lateral = parser.get("log_type") == "lateral_movement"
    is_correlation = parser.get("log_type") in {"correlation", "correlation_pcap"}
    is_handoff = parser.get("log_type") in {"investigation_handoff", "investigation_handoff_pcap"}
    allowed_formats = {"regex_syslog"} if is_system else {"json_lines"} if is_dns or is_ids or is_c2_dns or is_exfil or is_lateral or is_correlation or is_handoff else {"csv_syslog", "kv_syslog", "json_lines"}
    if parser_format not in allowed_formats:
        errors.append(
            "system parser format must be regex_syslog"
            if is_system
            else "DNS parser format must be json_lines"
            if is_dns
            else "IDS parser format must be json_lines"
            if is_ids
            else "C2 DNS parser format must be json_lines"
            if is_c2_dns
            else "exfiltration NetFlow parser format must be json_lines"
            if is_exfil
            else "lateral movement parser format must be json_lines"
            if is_lateral
            else "correlation evidence parser format must be json_lines"
            if is_correlation
            else "investigation handoff parser format must be json_lines"
            if is_handoff
            else "traffic parser format must be csv_syslog, kv_syslog or json_lines"
        )

    parse = parser.get("parse")
    if not isinstance(parse, dict):
        errors.append("parse must be an object")
    else:
        if parser_format == "csv_syslog":
            index_base = parse.get("index_base")
            if not isinstance(index_base, int) or isinstance(index_base, bool) or index_base != 0:
                errors.append("parse.index_base must be integer 0")
            for field, default in (("delimiter", ","), ("quotechar", '"')):
                value = parse.get(field, default)
                if not isinstance(value, str) or len(value) != 1:
                    errors.append(f"parse.{field} must be one character")
        elif parser_format == "kv_syslog":
            timestamp = parse.get("timestamp")
            key_pattern = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*$")
            if not isinstance(timestamp, dict):
                errors.append("kv parse.timestamp must be an object")
            else:
                sources = timestamp.get("sources")
                if (
                    not isinstance(sources, list)
                    or not 1 <= len(sources) <= 3
                    or not all(
                        isinstance(item, str) and key_pattern.fullmatch(item)
                        for item in sources
                    )
                ):
                    errors.append(
                        "kv parse.timestamp.sources must contain 1-3 safe key names"
                    )
                if timestamp.get("target", "event_time") != "event_time":
                    errors.append("kv parse.timestamp.target must be event_time")
                if not isinstance(timestamp.get("format"), str) or not timestamp.get("format"):
                    errors.append("kv parse.timestamp.format must be non-empty")
        elif parser_format == "regex_syslog":
            try:
                compiled = re.compile(str(parse.get("pattern", "")))
            except re.error as exc:
                errors.append(f"invalid regex parse.pattern: {exc}")
            else:
                if not compiled.groupindex:
                    errors.append("regex parse.pattern must define named capture groups")
        elif parser_format == "json_lines":
            timestamp=parse.get("timestamp")
            if not isinstance(timestamp,dict): errors.append("json_lines parse.timestamp must be an object")
            else:
                if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*",str(timestamp.get("source",""))): errors.append("json_lines timestamp source must be a safe JSON key")
                if timestamp.get("format")!="epoch_seconds": errors.append("json_lines timestamp format must be epoch_seconds")
                if timestamp.get("target","event_time")!="event_time": errors.append("json_lines timestamp target must be event_time")

    mapping = parser.get("mapping")
    mapped_fields: set[str] = set()
    if not isinstance(mapping, dict) or not mapping:
        errors.append("mapping must be a non-empty object")
    else:
        for raw_source, raw_target in mapping.items():
            if parser_format == "csv_syslog":
                try:
                    source = int(raw_source)
                except (TypeError, ValueError):
                    errors.append(f"mapping index is not an integer: {raw_source!r}")
                    continue
                if source < 0 or str(source) != str(raw_source):
                    errors.append(
                        f"mapping index must be a canonical non-negative integer: {raw_source!r}"
                    )
            elif parser_format == "kv_syslog" and (
                not isinstance(raw_source, str)
                or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", raw_source)
            ):
                errors.append(f"mapping key must be a safe key name: {raw_source!r}")
            elif parser_format == "regex_syslog" and (
                not isinstance(raw_source, str)
                or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", raw_source)
            ):
                errors.append(f"mapping capture must be a safe group name: {raw_source!r}")
            elif parser_format == "json_lines" and (not isinstance(raw_source,str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*",raw_source)):
                errors.append(f"JSON mapping key must be safe: {raw_source!r}")
            if not isinstance(raw_target, dict) or not isinstance(raw_target.get("field"), str):
                errors.append(f"mapping[{raw_source}] must contain a string field")
                continue
            field = raw_target["field"]
            if field in mapped_fields:
                errors.append(f"duplicate output field: {field}")
            mapped_fields.add(field)
            value_type = raw_target.get("type", "string")
            if value_type not in ALLOWED_VALUE_TYPES:
                errors.append(f"mapping[{raw_source}] has unsupported type: {value_type!r}")

    if parser_format == "kv_syslog" and isinstance(parse, dict) and isinstance(
        parse.get("timestamp"), dict
    ):
        timestamp_target = parse["timestamp"].get("target", "event_time")
        if timestamp_target in mapped_fields:
            errors.append(f"duplicate output field: {timestamp_target}")
        mapped_fields.add(timestamp_target)
    if parser_format == "json_lines" and isinstance(parse,dict) and isinstance(parse.get("timestamp"),dict):
        timestamp_target=parse["timestamp"].get("target","event_time")
        if timestamp_target in mapped_fields: errors.append(f"duplicate output field: {timestamp_target}")
        mapped_fields.add(timestamp_target)

    core_fields = (
        {"event_time", "device_name", "message"}
        if is_system
        else {"event_time","source_ip","destination_ip","dns_query","dns_qtype","dns_rcode"}
        if is_dns or is_c2_dns
        else {"event_time","source_ip","destination_ip","event_action","network_protocol","bytes_sent"}
        if is_exfil
        else {"event_time","source_ip","destination_ip","source_port","destination_port","event_action","network_protocol"}
        if is_lateral
        else ({"event_time","source_ip","event_action","vendor_fields.evidence_id","vendor_fields.source_role","vendor_fields.source_contract","vendor_fields.source_report_sha256","vendor_fields.source_view_sha256","vendor_fields.source_view_records","vendor_fields.parent_pcap_sha256","vendor_fields.unique_parent_conversations","vendor_fields.asset_id","vendor_fields.rule_hit","vendor_fields.clock_trusted","vendor_fields.simulation"} if parser.get("log_type")=="correlation_pcap" else {"event_time","source_ip","event_action","vendor_fields.evidence_id","vendor_fields.source_role","vendor_fields.source_contract","vendor_fields.source_report_sha256","vendor_fields.asset_id","vendor_fields.rule_hit","vendor_fields.clock_trusted"})
        if is_correlation
        else {"event_time","vendor_fields.source_contract","vendor_fields.total_evidence_records","vendor_fields.candidate_count"}
        if is_handoff
        else {"event_time","source_ip","destination_ip","alert_action","signature_id","signature","category","severity"}
        if is_ids
        else {"event_time", "source_ip", "destination_ip", "event_action"}
    )
    missing_core = sorted(core_fields - mapped_fields)
    if missing_core:
        errors.append("mapping misses analytical core fields: " + ", ".join(missing_core))

    validation = parser.get("validation", {})
    if not isinstance(validation, dict):
        errors.append("validation must be an object")
    else:
        required_output = validation.get("required_output", list(core_fields))
        if not isinstance(required_output, list) or not all(
            isinstance(item, str) for item in required_output
        ):
            errors.append("validation.required_output must be a list of field names")
        else:
            unavailable = sorted(set(required_output) - mapped_fields)
            if unavailable:
                errors.append(
                    "required_output fields are not mapped: " + ", ".join(unavailable)
                )

    detection = parser.get("detection", {})
    discriminator = detection.get("discriminator") if isinstance(detection, dict) else None
    if parser_format != "csv_syslog" and discriminator is not None:
        errors.append("detection.discriminator is supported only for csv_syslog")
    if discriminator is not None:
        if not isinstance(discriminator, dict):
            errors.append("detection.discriminator must be an object")
        else:
            field_index = discriminator.get("field_index")
            if (
                not isinstance(field_index, int)
                or isinstance(field_index, bool)
                or field_index < 0
            ):
                errors.append("discriminator.field_index must be a non-negative integer")
            accepted = discriminator.get("accepted_values")
            if not isinstance(accepted, list) or not accepted:
                errors.append("discriminator.accepted_values must be a non-empty list")
    return errors


def _render_spark_job(skill_name: str, parser_id: str) -> dict[str, Any]:
    parser = _parser_by_id(skill_name, parser_id)
    if parser.get("status") != "approved":
        raise ValueError("only approved published parsers can be rendered")
    compatibility_errors = _spark_template_parser_errors(parser)
    if compatibility_errors:
        raise ValueError(
            "parser is incompatible with trusted Spark CSV template: "
            + "; ".join(compatibility_errors)
        )
    log_type=parser.get("log_type")
    workflow_skill={"system":SYSTEM_WORKFLOW_SKILL,"dns":DNS_WORKFLOW_SKILL,"ids":IDS_WORKFLOW_SKILL,"c2_dns":C2_DNS_WORKFLOW_SKILL,"exfil_netflow":EXFIL_WORKFLOW_SKILL,"lateral_movement":LATERAL_WORKFLOW_SKILL,"correlation":CORRELATION_WORKFLOW_SKILL,"correlation_pcap":CORRELATION_WORKFLOW_SKILL,"investigation_handoff":HANDOFF_WORKFLOW_SKILL,"investigation_handoff_pcap":HANDOFF_WORKFLOW_SKILL}.get(log_type,WORKFLOW_SKILL)
    spark_template={"system":SYSTEM_SPARK_JOB_TEMPLATE,"dns":DNS_SPARK_JOB_TEMPLATE,"ids":IDS_SPARK_JOB_TEMPLATE,"c2_dns":C2_DNS_SPARK_JOB_TEMPLATE,"exfil_netflow":EXFIL_SPARK_JOB_TEMPLATE,"lateral_movement":LATERAL_SPARK_JOB_TEMPLATE,"correlation":CORRELATION_SPARK_JOB_TEMPLATE,"correlation_pcap":PCAP_CORRELATION_SPARK_JOB_TEMPLATE,"investigation_handoff":HANDOFF_SPARK_JOB_TEMPLATE,"investigation_handoff_pcap":PCAP_HANDOFF_SPARK_JOB_TEMPLATE}.get(log_type,SPARK_JOB_TEMPLATE)
    template_path, template = _published_resource(workflow_skill, spark_template)
    marker = "__PARSER_JSON_LITERAL__"
    if template.count(marker) != 1:
        raise ValueError(f"trusted Spark template must contain exactly one {marker} marker")
    # Canonicalize YAML integer keys to JSON strings so the MCP and standalone
    # renderers produce byte-for-byte identical source.
    parser_payload = json.loads(
        json.dumps(_public_parser(parser), ensure_ascii=False)
    )
    parser_json = json.dumps(
        parser_payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    code = template.replace(marker, repr(parser_json))
    if len(code.encode("utf-8")) > MAX_SPARK_JOB_BYTES:
        raise ValueError(f"rendered Spark job exceeds {MAX_SPARK_JOB_BYTES} bytes")
    try:
        compile(code, "<trusted-spark-job>", "exec")
    except SyntaxError as exc:
        raise ValueError(f"trusted Spark template rendered invalid Python: {exc}") from None
    return {
        "skill_name": skill_name,
        "parser_id": parser_id,
        "workflow_skill": workflow_skill,
        "template_path": spark_template,
        "template_sha256": hashlib.sha256(template.encode()).hexdigest(),
        "parser_sha256": hashlib.sha256(parser_json.encode()).hexdigest(),
        "code_sha256": hashlib.sha256(code.encode()).hexdigest(),
        "code": code,
        "execution": "not executed",
    }


def _spark_job_diagnostics(
    parser: dict[str, Any], code: str, expected_code: str
) -> tuple[list[str], list[str], dict[str, bool]]:
    errors: list[str] = []
    warnings: list[str] = []
    checks: dict[str, bool] = {}

    try:
        compile(code, "<submitted-spark-job>", "exec")
        checks["valid_python"] = True
    except SyntaxError as exc:
        checks["valid_python"] = False
        errors.append(f"invalid Python syntax: {exc}")

    forbidden_patterns = {
        "getArguments is not available in this Spark runtime": r"\bgetArguments\s*\(",
        "plain split is not quote-aware CSV parsing": r"\.split\(\s*['\"],['\"]\s*\)",
        "DataFrameReader.csv is outside the trusted raw-line parsing contract": r"spark\.read(?:\.[A-Za-z_][A-Za-z0-9_]*\([^\n]*\))*\.csv\s*\(",
        "delimiter is not a supported from_csv option; use sep": r"from_csv[\s\S]{0,500}['\"]delimiter['\"]\s*:",
        "do not subtract one from exact parser mapping indexes": r"(?:int\s*\(\s*source\s*\)|\bsource|\bindex)\s*-\s*1\b",
    }
    for message, pattern in forbidden_patterns.items():
        if re.search(pattern, code, re.IGNORECASE):
            errors.append(message)

    for match in re.finditer(r"\b(\d+)\s*->\s*(\d+)\b", code):
        declared, used = (int(value) for value in match.groups())
        if used == declared - 1:
            errors.append(
                f"index shift detected: parser index {declared} was rebased to {used}"
            )
            break
    if re.search(r"StructField\(\s*['\"]field_1['\"]", code) and not re.search(
        r"StructField\(\s*['\"]field_0['\"]", code
    ):
        errors.append("one-based field schema shifts zero-based parser indexes")

    required_fragments = {
        "uses_sys_argv_1": "sys.argv[1]",
        "uses_sys_argv_2": "sys.argv[2]",
        "uses_sys_argv_3": "sys.argv[3]",
        "uses_parser_mapping": 'PARSER["mapping"]',
        "writes_curated_parquet": ".parquet(CURATED_PATH)",
        "writes_report_text": ".text(REPORT_PATH)",
        "single_report_part": ".coalesce(1)",
    }
    if parser.get("log_type") == "system":
        required_fragments.update(
            {
                "uses_regex_extract": "regexp_extract",
                "uses_system_contract": '"system-event-report-v1"',
            }
        )
    elif parser.get("log_type") == "dns":
        required_fragments.update({"uses_from_json":"from_json","uses_dns_contract":'"dns-report-v1"',"uses_epoch_conversion":"from_unixtime"})
    elif parser.get("log_type") == "ids":
        required_fragments.update({"uses_from_json":"from_json","uses_ids_contract":'"ids-report-v1"',"uses_epoch_conversion":"from_unixtime","uses_ip_validation":"ipaddress.ip_address"})
    elif parser.get("log_type") == "c2_dns":
        required_fragments.update({"uses_from_json":"from_json","uses_c2_contract":'"c2-detection-report-v1"',"uses_c2_profile":'"dns-periodic-beacon-v1"',"uses_window_lag":"F.lag","uses_stddev":"stddev_pop","uses_epoch_conversion":"from_unixtime"})
    elif parser.get("log_type") == "exfil_netflow":
        required_fragments.update({"uses_from_json":"from_json","uses_exfil_contract":'"exfiltration-detection-report-v1"',"uses_exfil_profile":'"netflow-outbound-volume-v1"',"uses_direction":"src_internal","uses_ratio":"outbound_inbound_ratio","uses_epoch_conversion":"from_unixtime"})
    elif parser.get("log_type") == "lateral_movement":
        required_fragments.update({"uses_from_json":"from_json","uses_lateral_contract":'"lateral-movement-detection-report-v1"',"uses_lateral_profile":'"internal-remote-service-fanout-v1"',"uses_distinct_destinations":"countDistinct","uses_window_seconds":"window_seconds","uses_epoch_conversion":"from_unixtime"})
    elif parser.get("log_type") == "correlation":
        # The normalized correlation envelope has one fixed, versioned schema.
        required_fragments.pop("uses_parser_mapping")
        required_fragments.update({"uses_from_json":"from_json","uses_investigation_contract":'"security-investigation-report-v1"',"uses_correlation_profile":'"host-threat-sequence-v1"',"uses_asset_identity":"asset_id","uses_roles":"source_role","uses_dedup":"dropDuplicates","uses_first_window":"c2_to_exfil_seconds","uses_second_window":"exfil_to_lateral_seconds","uses_epoch_conversion":"from_unixtime"})
    elif parser.get("log_type") == "correlation_pcap":
        required_fragments.pop("uses_parser_mapping")
        required_fragments.update({"uses_from_json":"from_json","uses_investigation_contract":'"security-investigation-report-v2"',"uses_correlation_profile":'"pcap-host-threat-sequence-v2"',"uses_parent_hash":"parent_pcap_sha256","uses_unique_parent_count":"unique_parent_conversations","uses_view_accounting":"total_raw_view_records","uses_firewall_simulation":"firewall_sim","uses_roles":"source_role","uses_dedup":"dropDuplicates","uses_first_window":"c2_to_exfil_seconds","uses_second_window":"exfil_to_lateral_seconds","uses_epoch_conversion":"from_unixtime"})
    elif parser.get("log_type") == "investigation_handoff":
        required_fragments.pop("uses_parser_mapping")
        required_fragments.update({"uses_from_json":"from_json","uses_handoff_contract":'"security-investigation-handoff-v1"',"uses_handoff_policy":'"investigation-handoff-policy-v1"',"uses_needs_review":'"needs-review"',"uses_rule_hit":'"rule-hit"',"uses_timeline":"timeline","uses_source_hash":"source_sha256","uses_caveat":"not a confirmed incident or compromise"})
    elif parser.get("log_type") == "investigation_handoff_pcap":
        required_fragments.pop("uses_parser_mapping")
        required_fragments.update({"uses_from_json":"from_json","uses_handoff_contract":'"security-investigation-handoff-v2"',"uses_handoff_policy":'"shared-parent-investigation-handoff-policy-v2"',"uses_parent_hash":"pcap_sha256","uses_unique_parent":"unique_parent_conversations","uses_corroboration":"corroboration","uses_simulation":"simulation","uses_needs_review":'"needs-review"',"uses_rule_hit":'"rule-hit"',"uses_timeline":"timeline","uses_source_hash":"source_sha256","uses_caveat":"not a confirmed incident or compromise"})
    else:
        if parser.get("format") == "json_lines":
            required_fragments.update(
                {
                    "uses_from_json": "from_json",
                    "uses_epoch_conversion": "from_unixtime",
                }
            )
        else:
            required_fragments.update(
                {
                    "uses_from_csv": "from_csv",
                    "uses_sep_option": '"sep"',
                    "uses_quote_option": '"quote"',
                    "uses_permissive_mode": '"mode"',
                }
            )
    for check, fragment in required_fragments.items():
        present = fragment in code
        checks[check] = present
        if not present:
            errors.append(f"required trusted Spark pattern is missing: {fragment}")

    index_base = parser.get("parse", {}).get("index_base")
    checks["parser_index_base_is_zero"] = parser.get("format") != "csv_syslog" or (
        isinstance(index_base, int) and not isinstance(index_base, bool) and index_base == 0
    )
    if not checks["parser_index_base_is_zero"]:
        errors.append("CSV parser parse.index_base must be integer 0")
    checks["parser_format_supported"] = parser.get("format") in {
        "csv_syslog", "kv_syslog", "regex_syslog", "json_lines"
    }

    checks["parser_id_embedded"] = str(parser.get("id")) in code
    if not checks["parser_id_embedded"]:
        errors.append("approved parser id is not embedded in the Spark job")

    checks["matches_trusted_template"] = code == expected_code
    if not checks["matches_trusted_template"]:
        errors.append("job does not exactly match the trusted rendered Spark template")
        warnings.append("render a fresh job with log_skill_render_spark_job")
    return list(dict.fromkeys(errors)), warnings, checks


def _json_type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    return True


def _resolve_local_schema_ref(root_schema: dict[str, Any], reference: str) -> Any:
    if not reference.startswith("#/"):
        raise ValueError("only local JSON-Schema references are supported")
    node: Any = root_schema
    for raw_part in reference[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            raise ValueError(f"unresolved JSON-Schema reference: {reference}")
        node = node[part]
    return node


def _json_schema_errors(
    value: Any,
    schema: Any,
    location: str = "$",
    root_schema: dict[str, Any] | None = None,
    reference_stack: tuple[str, ...] = (),
) -> list[str]:
    """Validate the bounded JSON-Schema subset used by report contract v1."""
    if not isinstance(schema, dict):
        return [f"{location}: schema node must be an object"]
    if root_schema is None:
        root_schema = schema
    errors: list[str] = []
    reference = schema.get("$ref")
    if isinstance(reference, str):
        if reference in reference_stack:
            return [f"{location}: cyclic JSON-Schema reference: {reference}"]
        try:
            referenced_schema = _resolve_local_schema_ref(root_schema, reference)
        except ValueError as exc:
            return [f"{location}: {exc}"]
        errors.extend(
            _json_schema_errors(
                value,
                referenced_schema,
                location,
                root_schema,
                reference_stack + (reference,),
            )
        )
    all_of = schema.get("allOf")
    if isinstance(all_of, list):
        for child_schema in all_of:
            errors.extend(
                _json_schema_errors(
                    value, child_schema, location, root_schema, reference_stack
                )
            )
    expected_type = schema.get("type")
    if isinstance(expected_type, list):
        type_matches = any(_json_type_matches(value, item) for item in expected_type)
    elif isinstance(expected_type, str):
        type_matches = _json_type_matches(value, expected_type)
    else:
        type_matches = True
    if not type_matches:
        return [f"{location}: expected {expected_type}, got {type(value).__name__}"]
    if "const" in schema and value != schema["const"]:
        errors.append(f"{location}: must equal {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{location}: value is not in the allowed enum")
    if isinstance(value, dict):
        required = schema.get("required", [])
        for key in required if isinstance(required, list) else []:
            if key not in value:
                errors.append(f"{location}.{key}: required property is missing")
        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for key, child_schema in properties.items():
                if key in value:
                    errors.extend(
                        _json_schema_errors(
                            value[key], child_schema, f"{location}.{key}", root_schema
                        )
                    )
            additional = schema.get("additionalProperties")
            extra_keys = sorted(set(value) - set(properties))
            if additional is False:
                for key in extra_keys:
                    errors.append(f"{location}.{key}: additional property is not allowed")
            elif isinstance(additional, dict):
                for key in extra_keys:
                    errors.extend(
                        _json_schema_errors(
                            value[key], additional, f"{location}.{key}", root_schema
                        )
                    )
    elif isinstance(value, list):
        minimum_items = schema.get("minItems")
        if isinstance(minimum_items, int) and len(value) < minimum_items:
            errors.append(f"{location}: must contain at least {minimum_items} items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                errors.extend(
                    _json_schema_errors(
                        item, item_schema, f"{location}[{index}]", root_schema
                    )
                )
    elif isinstance(value, str):
        minimum_length = schema.get("minLength")
        if isinstance(minimum_length, int) and len(value) < minimum_length:
            errors.append(f"{location}: must contain at least {minimum_length} characters")
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        if isinstance(minimum, (int, float)) and value < minimum:
            errors.append(f"{location}: must be at least {minimum}")
    return errors


def _is_report_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_nonblank_report_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _report_timestamp(
    value: Any, name: str, errors: list[str]
) -> datetime | None:
    if not _is_nonblank_report_string(value):
        errors.append(f"$.{name}: must be a non-blank timestamp string")
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"$.{name}: must be an ISO-8601-compatible timestamp")
        return None


def _report_traffic_table_errors(
    rows: Any,
    field: str,
    dimension: str | tuple[str, ...],
    limit: int,
    order_by: str,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(rows, list):
        return errors
    if len(rows) > limit:
        errors.append(f"$.{field}: contains {len(rows)} rows; maximum is {limit}")
    dimensions = (dimension,) if isinstance(dimension, str) else dimension
    seen: set[tuple[Any, ...]] = set()
    ordering: list[tuple[int, int]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        values = tuple(row.get(name) for name in dimensions)
        for name, value in zip(dimensions, values):
            if not _is_nonblank_report_string(value):
                errors.append(f"$.{field}[{index}].{name}: must be non-blank")
        if all(_is_nonblank_report_string(value) for value in values):
            if values in seen:
                label = ", ".join(dimensions)
                errors.append(
                    f"$.{field}[{index}]: duplicate ({label}) value {values!r}"
                )
            seen.add(values)
        metrics = [
            row.get(name)
            for name in ("sessions", "bytes_sent", "bytes_received", "total_bytes")
        ]
        if all(_is_report_integer(item) for item in metrics):
            sessions, sent, received, total = metrics
            if total != sent + received:
                errors.append(
                    f"$.{field}[{index}].total_bytes: must equal "
                    "bytes_sent + bytes_received"
                )
            ordering.append(
                (sessions, total) if order_by == "sessions" else (total, sessions)
            )
    if ordering != sorted(ordering, reverse=True):
        errors.append(
            f"$.{field}: rows are not ranked by {order_by}, then the secondary metric"
        )
    return errors


def _report_semantic_errors(report: dict[str, Any]) -> list[str]:
    """Apply trusted analytical invariants for security-report-v1."""
    errors: list[str] = []
    parser = report.get("parser")
    if isinstance(parser, dict):
        for name in ("id", "version", "vendor", "product", "log_type"):
            if not _is_nonblank_report_string(parser.get(name)):
                errors.append(f"$.parser.{name}: must be non-blank")

    total_records = report.get("total_records")
    parse_quality = report.get("parse_quality")
    if isinstance(parse_quality, dict) and _is_report_integer(total_records):
        if not parse_quality:
            errors.append("$.parse_quality: must contain at least one status count")
        invalid_statuses = sorted(
            name
            for name in parse_quality
            if name not in {"parsed", "partial", "failed"}
        )
        if invalid_statuses:
            errors.append(
                "$.parse_quality: statuses are limited to parsed, partial, and failed"
            )
        counts = [
            value for value in parse_quality.values() if _is_report_integer(value)
        ]
        if len(counts) == len(parse_quality) and sum(counts) != total_records:
            errors.append(
                "$.parse_quality: integer status counts must sum to total_records"
            )

    field_coverage = report.get("field_coverage")
    mapped_fields: set[str] | None = None
    if isinstance(field_coverage, dict) and isinstance(
        field_coverage.get("mapped"), list
    ):
        mapped = field_coverage["mapped"]
        if all(_is_nonblank_report_string(item) for item in mapped):
            mapped_fields = set(mapped)
            if len(mapped_fields) != len(mapped):
                errors.append("$.field_coverage.mapped: field names must be unique")

    def requires_rows(table: str) -> bool:
        if table not in REPORT_REQUIRED_NONEMPTY_TABLES:
            return False
        if mapped_fields is None:
            return True
        return REPORT_TABLE_SOURCE_FIELDS[table] in mapped_fields

    event_min = _report_timestamp(report.get("event_time_min"), "event_time_min", errors)
    event_max = _report_timestamp(report.get("event_time_max"), "event_time_max", errors)
    if event_min is not None and event_max is not None:
        try:
            if event_min > event_max:
                errors.append("$.event_time_min: must not be later than event_time_max")
        except TypeError:
            errors.append(
                "$.event_time_min/event_time_max: timezone awareness must match"
            )

    for field, limit in REPORT_COUNT_TABLES.items():
        rows = report.get(field)
        if not isinstance(rows, list):
            continue
        if requires_rows(field) and not rows:
            errors.append(
                f"$.{field}: cannot be empty for a non-empty traffic dataset"
            )
        if len(rows) > limit:
            errors.append(f"$.{field}: contains {len(rows)} rows; maximum is {limit}")
        values: set[str] = set()
        counts: list[int] = []
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            value = row.get("value")
            if not _is_nonblank_report_string(value):
                errors.append(f"$.{field}[{index}].value: must be non-blank")
            elif value in values:
                errors.append(f"$.{field}[{index}].value: duplicate value {value!r}")
            else:
                values.add(value)
            if _is_report_integer(row.get("count")):
                counts.append(row["count"])
        if counts != sorted(counts, reverse=True):
            errors.append(f"$.{field}: rows are not ranked by count")

    for field, (dimension, limit, order_by) in REPORT_TRAFFIC_TABLES.items():
        rows = report.get(field)
        if requires_rows(field) and isinstance(rows, list) and not rows:
            errors.append(
                f"$.{field}: cannot be empty for a non-empty traffic dataset"
            )
        errors.extend(
            _report_traffic_table_errors(rows, field, dimension, limit, order_by)
        )

    nat = report.get("nat")
    if isinstance(nat, dict) and _is_report_integer(total_records):
        nat_count = nat.get("nat_sessions")
        source_count = nat.get("source_nat_sessions")
        destination_count = nat.get("destination_nat_sessions")
        for name, value in (
            ("nat_sessions", nat_count),
            ("source_nat_sessions", source_count),
            ("destination_nat_sessions", destination_count),
        ):
            if _is_report_integer(value) and value > total_records:
                errors.append(f"$.nat.{name}: cannot exceed total_records")
        if all(
            _is_report_integer(value)
            for value in (nat_count, source_count, destination_count)
        ):
            if source_count > nat_count or destination_count > nat_count:
                errors.append(
                    "$.nat: source/destination NAT counts cannot exceed nat_sessions"
                )
        for field, dimension, translated in (
            (
                "top_source_translations",
                ("source_ip", "source_translated_ip"),
                "source_translated_ip",
            ),
            (
                "top_destination_translations",
                ("destination_ip", "destination_translated_ip"),
                "destination_translated_ip",
            ),
        ):
            rows = nat.get(field)
            errors.extend(
                _report_traffic_table_errors(
                    rows, f"nat.{field}", dimension, 20, "sessions"
                )
            )
            original = dimension[0]
            if isinstance(rows, list):
                for index, row in enumerate(rows):
                    if not isinstance(row, dict):
                        continue
                    translated_value = row.get(translated)
                    if (
                        not _is_nonblank_report_string(translated_value)
                        or translated_value == "0.0.0.0"
                    ):
                        errors.append(
                            f"$.nat.{field}[{index}].{translated}: "
                            "must be an observed translated IP"
                        )
                    if row.get(original) == translated_value:
                        errors.append(
                            f"$.nat.{field}[{index}]: original and translated IP must differ"
                        )
    return errors


def _system_report_semantic_errors(report: dict[str, Any]) -> list[str]:
    """Apply deterministic invariants for system-event-report-v1."""
    errors: list[str] = []
    total = report.get("total_records")
    quality = report.get("parse_quality")
    if isinstance(quality, dict) and _is_report_integer(total):
        parsed = quality.get("parsed")
        failed = quality.get("failed")
        if all(_is_report_integer(value) for value in (parsed, failed)) and parsed + failed != total:
            errors.append("$.parse_quality: parsed + failed must equal total_records")

    event_min = _report_timestamp(report.get("event_time_min"), "event_time_min", errors)
    event_max = _report_timestamp(report.get("event_time_max"), "event_time_max", errors)
    if event_min is not None and event_max is not None and event_min > event_max:
        errors.append("$.event_time_min: must not be later than event_time_max")

    for field in ("top_devices", "top_modules", "top_severities", "top_event_ids"):
        rows = report.get(field)
        if not isinstance(rows, list):
            continue
        values: set[str] = set()
        counts: list[int] = []
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            value = row.get("value")
            if not _is_nonblank_report_string(value):
                errors.append(f"$.{field}[{index}].value: must be non-blank")
            elif value in values:
                errors.append(f"$.{field}[{index}].value: duplicate value {value!r}")
            else:
                values.add(value)
            if _is_report_integer(row.get("count")):
                counts.append(row["count"])
        if counts != sorted(counts, reverse=True):
            errors.append(f"$.{field}: rows are not ranked by count")

    auth = report.get("authentication_events")
    if isinstance(auth, dict) and _is_report_integer(total):
        success = auth.get("login_success")
        failure = auth.get("login_failure")
        if all(_is_report_integer(value) for value in (success, failure)) and success + failure > total:
            errors.append("$.authentication_events: counts cannot exceed total_records")
    return errors

def _dns_report_semantic_errors(report: dict[str, Any]) -> list[str]:
    errors=[]; total=report.get("total_records"); quality=report.get("parse_quality")
    if isinstance(quality,dict) and _is_report_integer(total):
        parsed,failed=quality.get("parsed"),quality.get("failed")
        if all(_is_report_integer(v) for v in (parsed,failed)) and parsed+failed!=total: errors.append("$.parse_quality: parsed + failed must equal total_records")
    event_min=_report_timestamp(report.get("event_time_min"),"event_time_min",errors); event_max=_report_timestamp(report.get("event_time_max"),"event_time_max",errors)
    if event_min is not None and event_max is not None and event_min>event_max: errors.append("$.event_time_min: must not be later than event_time_max")
    for field in ("top_clients","top_resolvers","top_queries","top_qtypes","top_rcodes"):
        rows=report.get(field)
        if not isinstance(rows,list): continue
        values=set(); counts=[]
        for index,row in enumerate(rows):
            if not isinstance(row,dict): continue
            value=row.get("value")
            if not _is_nonblank_report_string(value): errors.append(f"$.{field}[{index}].value: must be non-blank")
            elif value in values: errors.append(f"$.{field}[{index}].value: duplicate value {value!r}")
            else: values.add(value)
            if _is_report_integer(row.get("count")): counts.append(row["count"])
        if counts!=sorted(counts,reverse=True): errors.append(f"$.{field}: rows are not ranked by count")
    summary=report.get("response_summary")
    if isinstance(summary,dict) and _is_report_integer(total):
        response_counts=[summary.get(name) for name in ("noerror","nxdomain","other")]
        if all(_is_report_integer(v) for v in response_counts) and sum(response_counts)!=total: errors.append("$.response_summary: noerror + nxdomain + other must equal total_records")
        if _is_report_integer(summary.get("rejected")) and summary["rejected"]>total: errors.append("$.response_summary.rejected: cannot exceed total_records")
    indicators=report.get("query_shape_indicators")
    if isinstance(indicators,dict) and _is_report_integer(total):
        for name in ("long_query_over_80","many_labels_six_or_more"):
            if _is_report_integer(indicators.get(name)) and indicators[name]>total: errors.append(f"$.query_shape_indicators.{name}: cannot exceed total_records")
    return errors


def _ids_report_semantic_errors(report: dict[str, Any]) -> list[str]:
    errors=[]; total=report.get("total_records"); quality=report.get("parse_quality")
    if isinstance(quality,dict) and _is_report_integer(total):
        parsed,failed=quality.get("parsed"),quality.get("failed")
        if all(_is_report_integer(v) for v in (parsed,failed)) and parsed+failed!=total: errors.append("$.parse_quality: parsed + failed must equal total_records")
    event_min=_report_timestamp(report.get("event_time_min"),"event_time_min",errors); event_max=_report_timestamp(report.get("event_time_max"),"event_time_max",errors)
    if event_min is not None and event_max is not None and event_min>event_max: errors.append("$.event_time_min: must not be later than event_time_max")
    for field in ("top_signatures","top_signature_ids","top_categories","top_severities","top_alert_actions","top_source_ips","top_destination_ips","top_applications","top_protocols"):
        rows=report.get(field)
        if not isinstance(rows,list): continue
        values=set(); counts=[]
        for index,row in enumerate(rows):
            if not isinstance(row,dict): continue
            value=row.get("value")
            if not _is_nonblank_report_string(value): errors.append(f"$.{field}[{index}].value: must be non-blank")
            elif value in values: errors.append(f"$.{field}[{index}].value: duplicate value {value!r}")
            else: values.add(value)
            if _is_report_integer(row.get("count")): counts.append(row["count"])
        if counts!=sorted(counts,reverse=True): errors.append(f"$.{field}: rows are not ranked by count")
    summary=report.get("severity_summary")
    if isinstance(summary,dict) and _is_report_integer(total):
        counts=[summary.get(name) for name in ("critical","high","medium","low_or_info")]
        if all(_is_report_integer(value) for value in counts) and sum(counts)!=total: errors.append("$.severity_summary: severity counts must sum to total_records")
    return errors


def _c2_dns_report_semantic_errors(report: dict[str, Any]) -> list[str]:
    errors=[]; total=report.get("total_records"); quality=report.get("parse_quality")
    if isinstance(quality,dict) and _is_report_integer(total):
        parsed,failed=quality.get("parsed"),quality.get("failed")
        if all(_is_report_integer(v) for v in (parsed,failed)) and parsed+failed!=total: errors.append("$.parse_quality: parsed + failed must equal total_records")
    event_min=_report_timestamp(report.get("event_time_min"),"event_time_min",errors); event_max=_report_timestamp(report.get("event_time_max"),"event_time_max",errors)
    if event_min is not None and event_max is not None and event_min>event_max: errors.append("$.event_time_min: must not be later than event_time_max")
    detections=report.get("detections")
    if isinstance(detections,list):
        keys=set(); counts=[]; supporting=0
        for index,row in enumerate(detections):
            if not isinstance(row,dict): continue
            key=(row.get("source_ip"),row.get("query"))
            if key in keys: errors.append(f"$.detections[{index}]: duplicate source/query")
            keys.add(key)
            if row.get("query")=="update.vendor.example.test": errors.append(f"$.detections[{index}].query: allowlisted query cannot be detected")
            if _is_report_integer(row.get("event_count")): counts.append(row["event_count"]); supporting+=row["event_count"]
        if counts!=sorted(counts,reverse=True): errors.append("$.detections: rows are not ranked by event_count")
        summary=report.get("detection_summary")
        if isinstance(summary,dict):
            if summary.get("detected_entities")!=len(detections): errors.append("$.detection_summary.detected_entities: must equal detections length")
            if summary.get("supporting_events")!=supporting: errors.append("$.detection_summary.supporting_events: must equal detection event counts")
    return errors


def _exfil_report_semantic_errors(report: dict[str, Any]) -> list[str]:
    errors=[]; total=report.get("total_records"); quality=report.get("parse_quality")
    if isinstance(quality,dict) and _is_report_integer(total):
        parsed,failed=quality.get("parsed"),quality.get("failed")
        if all(_is_report_integer(v) for v in (parsed,failed)) and parsed+failed!=total: errors.append("$.parse_quality: parsed + failed must equal total_records")
    event_min=_report_timestamp(report.get("event_time_min"),"event_time_min",errors); event_max=_report_timestamp(report.get("event_time_max"),"event_time_max",errors)
    if event_min is not None and event_max is not None and event_min>event_max: errors.append("$.event_time_min: must not be later than event_time_max")
    rows=report.get("detections")
    profile=report.get("detection_profile",{})
    threshold=profile.get("minimum_outbound_bytes") if isinstance(profile,dict) else None
    if isinstance(rows,list):
        keys=set(); ordering=[]; flow_sum=0; byte_sum=0
        for index,row in enumerate(rows):
            if not isinstance(row,dict): continue
            key=(row.get("internal_ip"),row.get("external_ip"))
            if key in keys: errors.append(f"$.detections[{index}]: duplicate internal/external pair")
            keys.add(key)
            if row.get("external_ip")=="203.0.113.10": errors.append(f"$.detections[{index}].external_ip: allowlisted destination cannot be detected")
            if _is_report_integer(threshold) and _is_report_integer(row.get("outbound_bytes")) and row["outbound_bytes"]<threshold: errors.append(f"$.detections[{index}].outbound_bytes: below selected profile threshold")
            if _is_report_integer(row.get("outbound_bytes")): ordering.append(row["outbound_bytes"]); byte_sum+=row["outbound_bytes"]
            if _is_report_integer(row.get("outbound_flows")): flow_sum+=row["outbound_flows"]
        if ordering!=sorted(ordering,reverse=True): errors.append("$.detections: rows are not ranked by outbound_bytes")
        summary=report.get("detection_summary")
        if isinstance(summary,dict):
            if summary.get("detected_pairs")!=len(rows): errors.append("$.detection_summary.detected_pairs: must equal detections length")
            if summary.get("supporting_outbound_flows")!=flow_sum: errors.append("$.detection_summary.supporting_outbound_flows: must equal detection flow counts")
            if summary.get("supporting_outbound_bytes")!=byte_sum: errors.append("$.detection_summary.supporting_outbound_bytes: must equal detection byte counts")
    return errors


def _lateral_report_semantic_errors(report: dict[str, Any]) -> list[str]:
    errors=[]; total=report.get("total_records"); quality=report.get("parse_quality")
    if isinstance(quality,dict) and _is_report_integer(total):
        parsed,failed=quality.get("parsed"),quality.get("failed")
        if all(_is_report_integer(v) for v in (parsed,failed)) and parsed+failed!=total: errors.append("$.parse_quality: parsed + failed must equal total_records")
    event_min=_report_timestamp(report.get("event_time_min"),"event_time_min",errors); event_max=_report_timestamp(report.get("event_time_max"),"event_time_max",errors)
    if event_min is not None and event_max is not None and event_min>event_max: errors.append("$.event_time_min: must not be later than event_time_max")
    rows=report.get("detections")
    if isinstance(rows,list):
        keys=set(); ordering=[]; connection_sum=0; destination_sum=0
        for index,row in enumerate(rows):
            if not isinstance(row,dict): continue
            source=row.get("source_ip")
            if source in keys: errors.append(f"$.detections[{index}]: duplicate source_ip")
            keys.add(source)
            if source=="10.70.0.10": errors.append(f"$.detections[{index}].source_ip: allowlisted source cannot be detected")
            if _is_report_integer(row.get("distinct_destinations")): ordering.append(row["distinct_destinations"]); destination_sum+=row["distinct_destinations"]
            if _is_report_integer(row.get("successful_connections")): connection_sum+=row["successful_connections"]
            if _is_report_integer(row.get("window_seconds")) and row["window_seconds"]>300: errors.append(f"$.detections[{index}].window_seconds: exceeds profile maximum")
        if ordering!=sorted(ordering,reverse=True): errors.append("$.detections: rows are not ranked by distinct_destinations")
        summary=report.get("detection_summary")
        if isinstance(summary,dict):
            if summary.get("detected_sources")!=len(rows): errors.append("$.detection_summary.detected_sources: must equal detections length")
            if summary.get("supporting_connections")!=connection_sum: errors.append("$.detection_summary.supporting_connections: must equal detection connection counts")
            if summary.get("distinct_destinations")!=destination_sum: errors.append("$.detection_summary.distinct_destinations: must equal detection destination counts")
    return errors


def _correlation_report_semantic_errors(report: dict[str, Any]) -> list[str]:
    errors=[]; total=report.get("total_evidence_records"); quality=report.get("parse_quality",{})
    if _is_report_integer(total) and all(_is_report_integer(quality.get(x)) for x in ("parsed","failed")) and quality["parsed"]+quality["failed"]!=total: errors.append("$.parse_quality: parsed + failed must equal total_evidence_records")
    sources=report.get("source_provenance",[]); roles=[x.get("role") for x in sources if isinstance(x,dict)]
    if roles!=["dns_c2","network_exfil","east_west_lateral"]: errors.append("$.source_provenance: roles must be exact and ordered")
    if len(set(roles))!=len(roles): errors.append("$.source_provenance: duplicate roles")
    rows=report.get("investigation_candidates",[]); assets=set()
    for index,row in enumerate(rows if isinstance(rows,list) else []):
        if not isinstance(row,dict): continue
        if row.get("asset_id") in assets: errors.append(f"$.investigation_candidates[{index}]: duplicate asset_id")
        assets.add(row.get("asset_id"))
        if row.get("asset_id")!="asset-066": errors.append(f"$.investigation_candidates[{index}].asset_id: unexpected bounded candidate")
        for field in ("c2_to_exfil_seconds","exfil_to_lateral_seconds"):
            value=row.get(field)
            if _is_report_integer(value) and not 0<=value<=1800: errors.append(f"$.investigation_candidates[{index}].{field}: outside profile window")
    summary=report.get("correlation_summary",{})
    if isinstance(rows,list) and isinstance(summary,dict):
        if summary.get("candidate_count")!=len(rows): errors.append("$.correlation_summary.candidate_count: must equal candidate length")
        if summary.get("supporting_evidence_count")!=sum(len(x.get("supporting_evidence_ids",[])) for x in rows if isinstance(x,dict)): errors.append("$.correlation_summary.supporting_evidence_count: mismatch")
    return errors


def _pcap_correlation_report_semantic_errors(report: dict[str, Any]) -> list[str]:
    errors=[]; expected=["dns_c2","network_exfil","east_west_lateral","ids_alert","firewall_sim"]
    total=report.get("total_evidence_records"); quality=report.get("parse_quality",{})
    if not _is_report_integer(total) or total<5 or quality!={"parsed":total,"failed":0}: errors.append("$: shared-parent correlation must contain at least five fully parsed evidence rows")
    sources=report.get("source_provenance",[]); roles=[x.get("role") for x in sources if isinstance(x,dict)]
    if roles!=expected: errors.append("$.source_provenance: roles must be exact and ordered")
    parent=report.get("parent_evidence",{}); views=parent.get("raw_view_records",{}) if isinstance(parent,dict) else {}
    expected_views={"dns_c2":120,"network_exfil":100000,"east_west_lateral":100000,"ids_alert":340,"firewall_sim":100000}
    if views!=expected_views or parent.get("total_raw_view_records")!=300460 or parent.get("unique_parent_conversations")!=100000: errors.append("$.parent_evidence: view accounting mismatch")
    valid_view_counts=isinstance(views,dict) and all(_is_report_integer(v) for v in views.values())
    if not valid_view_counts or sum(views.values())!=300460: errors.append("$.parent_evidence.raw_view_records: sum mismatch")
    rows=report.get("investigation_candidates",[]); assets=set()
    for index,row in enumerate(rows if isinstance(rows,list) else []):
        if not isinstance(row,dict): continue
        if row.get("asset_id") in assets: errors.append(f"$.investigation_candidates[{index}]: duplicate asset_id")
        assets.add(row.get("asset_id"))
        expected_entities={"asset-066":"10.70.0.66","asset-control":"10.70.10.1"}
        if row.get("asset_id") not in expected_entities or row.get("entity_ip")!=expected_entities.get(row.get("asset_id")): errors.append(f"$.investigation_candidates[{index}]: unexpected bounded candidate")
        if row.get("supporting_roles")!=expected or len(row.get("supporting_evidence_ids",[]))!=5: errors.append(f"$.investigation_candidates[{index}]: five-role support mismatch")
        if row.get("c2_to_exfil_seconds")!=660 or row.get("exfil_to_lateral_seconds")!=1800: errors.append(f"$.investigation_candidates[{index}]: sequence timing mismatch")
        if row.get("corroboration")!={"ids_alert_records":340,"firewall_simulated_signal_sessions":265}: errors.append(f"$.investigation_candidates[{index}].corroboration: mismatch")
    summary=report.get("correlation_summary",{})
    if isinstance(rows,list) and summary!={"candidate_count":len(rows),"supporting_evidence_count":sum(len(x.get("supporting_evidence_ids",[])) for x in rows if isinstance(x,dict))}: errors.append("$.correlation_summary: count mismatch")
    caveats=report.get("caveats",[])
    if not any("not unique sessions" in x for x in caveats if isinstance(x,str)): errors.append("$.caveats: IDS packet/session caveat missing")
    if not any("simulated" in x and "cannot prove" in x for x in caveats if isinstance(x,str)): errors.append("$.caveats: simulated firewall provenance caveat missing")
    return errors


def _handoff_report_semantic_errors(report: dict[str, Any]) -> list[str]:
    errors=[]; expected_roles=["dns_c2","network_exfil","east_west_lateral"]
    if report.get("total_records")!=1 or report.get("parse_quality")!={"parsed":1,"failed":0}: errors.append("$: handoff must derive from exactly one parsed correlation report")
    policy=report.get("handoff_policy",{})
    if policy!={"id":"investigation-handoff-policy-v1","source_contract":"security-investigation-report-v1","target":"vendor-neutral-siem","timeline_roles":expected_roles}: errors.append("$.handoff_policy: immutable policy mismatch")
    source=report.get("source_report",{})
    if source.get("canonical_sha256")!="3240bad94fb8c2b9f7a90e71039b960ab3bb72cf744d68ec902b1fb690e4206a" or source.get("total_evidence_records")!=100000: errors.append("$.source_report: correlation provenance mismatch")
    cases=report.get("cases",[])
    if not isinstance(cases,list) or len(cases)!=1: errors.append("$.cases: exactly one bounded case is required")
    else:
        case=cases[0]
        if case.get("case_id")!="case-3240bad94fb8c2b9-asset-066" or case.get("asset_id")!="asset-066": errors.append("$.cases[0]: case identity mismatch")
        for field,value in (("priority","high"),("disposition","needs-review"),("verdict","rule-hit")):
            if case.get(field)!=value: errors.append(f"$.cases[0].{field}: immutable policy mismatch")
        timeline=case.get("timeline",[]); roles=[x.get("role") for x in timeline if isinstance(x,dict)]; sequences=[x.get("sequence") for x in timeline if isinstance(x,dict)]
        if roles!=expected_roles or sequences!=[1,2,3]: errors.append("$.cases[0].timeline: roles/order mismatch")
        expected_ids=["dns_c2-000000000000","network_exfil-000000000000","east_west_lateral-000000000000"]
        if [x.get("evidence_id") for x in timeline if isinstance(x,dict)]!=expected_ids: errors.append("$.cases[0].timeline: evidence IDs mismatch")
        if len({x.get("source_sha256") for x in timeline if isinstance(x,dict)})!=3: errors.append("$.cases[0].timeline: source hashes must be complete and distinct")
        if case.get("caveat")!="Rule hit only; not a confirmed incident or compromise.": errors.append("$.cases[0].caveat: immutable caveat mismatch")
    summary=report.get("handoff_summary",{})
    if summary!={"case_count":1,"timeline_event_count":3,"needs_review_count":1}: errors.append("$.handoff_summary: count mismatch")
    return errors


def _pcap_handoff_report_semantic_errors(report: dict[str, Any]) -> list[str]:
    errors=[]; primary=["dns_c2","network_exfil","east_west_lateral"]; supporting=["ids_alert","firewall_sim"]
    if report.get("total_records")!=1 or report.get("parse_quality")!={"parsed":1,"failed":0}: errors.append("$: v2 handoff must derive from exactly one parsed correlation report")
    parent=report.get("parent_evidence",{})
    if parent.get("pcap_sha256")!="fa9d5c21eb157e0630ff7524a656ea8bbf761951d602d238c4a35c9cb81ffa5a" or parent.get("unique_parent_conversations")!=100000 or parent.get("total_raw_view_records")!=300460: errors.append("$.parent_evidence: shared-parent provenance mismatch")
    if parent.get("semantics")!="overlapping derived views of one parent PCAP; raw view records are not additive unique events": errors.append("$.parent_evidence.semantics: non-additive accounting caveat mismatch")
    cases=report.get("cases",[])
    if not isinstance(cases,list) or len(cases)!=1: errors.append("$.cases: exactly one bounded case is required")
    else:
        case=cases[0];timeline=case.get("timeline",[]);corroboration=case.get("corroboration",[])
        if [x.get("role") for x in timeline if isinstance(x,dict)]!=primary or [x.get("sequence") for x in timeline if isinstance(x,dict)]!=[1,2,3]: errors.append("$.cases[0].timeline: primary roles/order mismatch")
        if [x.get("role") for x in corroboration if isinstance(x,dict)]!=supporting: errors.append("$.cases[0].corroboration: supporting roles/order mismatch")
        if len({x.get("source_sha256") for x in timeline+corroboration if isinstance(x,dict)})!=5: errors.append("$.cases[0]: five distinct source hashes are required")
        if len(corroboration)==2 and (corroboration[0].get("simulation") is not False or corroboration[1].get("simulation") is not True): errors.append("$.cases[0].corroboration: firewall-only simulation markers mismatch")
        if [x.get("records") for x in corroboration if isinstance(x,dict)]!=[340,265]: errors.append("$.cases[0].corroboration: record counts mismatch")
        caveats=case.get("caveats",[])
        if not any("not a confirmed" in x for x in caveats if isinstance(x,str)) or not any("simulated" in x for x in caveats if isinstance(x,str)): errors.append("$.cases[0].caveats: required interpretation limits missing")
    return errors


@mcp.tool()
def log_skill_list() -> dict[str, Any]:
    """List approved parser and parserless workflow skills."""
    skills = []
    for path in _skill_dirs():
        try:
            skill = _load_skill(path)
            skills.append({
                "name": skill["name"],
                "description": skill["description"],
                "kind": skill["kind"],
                "resource_count": len(skill["resources"]),
                "parsers": [{key: parser.get(key) for key in ("id", "version", "vendor", "product", "firmware", "log_type", "format", "status")} for parser in skill["parsers"]],
            })
        except (OSError, ValueError, yaml.YAMLError) as exc:
            skills.append({"name": path.name, "invalid": True, "error": str(exc)})
    return {"skills_root": str(SKILLS_DIR), "count": len(skills), "skills": skills}


@mcp.tool()
def log_skill_search(query: str) -> dict[str, Any]:
    """Search skill metadata and parser vendor/product/log-type fields."""
    needle = query.strip().lower()
    if not needle:
        raise ValueError("query must not be empty")
    matches = []
    for path in _skill_dirs():
        try:
            skill = _load_skill(path)
            haystack = " ".join([skill["name"], skill["description"]] + [" ".join(str(parser.get(k, "")) for k in ("id", "vendor", "product", "log_type")) for parser in skill["parsers"]]).lower()
            if needle in haystack:
                matches.append({"name": skill["name"], "description": skill["description"], "parser_ids": [parser["id"] for parser in skill["parsers"]]})
        except (OSError, ValueError, yaml.YAMLError):
            continue
    return {"query": query, "count": len(matches), "matches": matches}


@mcp.tool()
def log_skill_get(skill_name: str, include_body: bool = True) -> dict[str, Any]:
    """Get one published skill and its parser contracts."""
    skill = _load_skill(_safe_child(SKILLS_DIR, skill_name))
    result = {
        "name": skill["name"],
        "description": skill["description"],
        "kind": skill["kind"],
        "resources": skill["resources"],
        "parsers": [
            {key: value for key, value in parser.items() if key != "_path"}
            for parser in skill["parsers"]
        ],
    }
    if include_body:
        result["body"] = skill["body"]
    return result


@mcp.tool()
def log_skill_list_resources(skill_name: str) -> dict[str, Any]:
    """List readable published references, scripts, and assets; never execute them."""
    path = _safe_child(SKILLS_DIR, skill_name)
    skill = _load_skill(path)
    return {
        "skill_name": skill["name"],
        "count": len(skill["resources"]),
        "resources": skill["resources"],
        "execution": "disabled",
    }


@mcp.tool()
def log_skill_read_resource(skill_name: str, resource_path: str) -> dict[str, Any]:
    """Read one allowlisted UTF-8 published resource as inert text; never execute it."""
    path = _safe_child(SKILLS_DIR, skill_name)
    resource = _safe_resource_path(path, resource_path)
    content = _read_limited(resource, MAX_RESOURCE_BYTES)
    metadata = _resource_metadata(path, resource_path)
    return {
        "skill_name": skill_name,
        **metadata,
        "content": content,
        "execution": "disabled",
    }


@mcp.tool()
def log_skill_render_spark_job(skill_name: str, parser_id: str) -> dict[str, Any]:
    """Render trusted Spark code with one approved parser; never execute skill code."""
    return _render_spark_job(skill_name, parser_id)


@mcp.tool()
def log_skill_validate_spark_job(
    skill_name: str, parser_id: str, code: str
) -> dict[str, Any]:
    """Check Spark code against its approved parser and exact trusted template."""
    if not isinstance(code, str) or not code.strip():
        raise ValueError("code must be a non-empty string")
    if len(code.encode("utf-8")) > MAX_SPARK_JOB_BYTES:
        raise ValueError(f"code exceeds {MAX_SPARK_JOB_BYTES} bytes")
    parser = _parser_by_id(skill_name, parser_id)
    workflow_skill = {"system":SYSTEM_WORKFLOW_SKILL,"dns":DNS_WORKFLOW_SKILL,"ids":IDS_WORKFLOW_SKILL,"c2_dns":C2_DNS_WORKFLOW_SKILL,"exfil_netflow":EXFIL_WORKFLOW_SKILL,"lateral_movement":LATERAL_WORKFLOW_SKILL,"correlation":CORRELATION_WORKFLOW_SKILL,"correlation_pcap":CORRELATION_WORKFLOW_SKILL,"investigation_handoff":HANDOFF_WORKFLOW_SKILL,"investigation_handoff_pcap":HANDOFF_WORKFLOW_SKILL}.get(parser.get("log_type"),WORKFLOW_SKILL)
    policy = _published_json_resource(workflow_skill, SPARK_POLICY_RESOURCE)
    expected = _render_spark_job(skill_name, parser_id)
    errors, warnings, checks = _spark_job_diagnostics(parser, code, expected["code"])
    return {
        "skill_name": skill_name,
        "parser_id": parser_id,
        "policy": policy.get(
            "policy_id", policy.get("id", policy.get("version", "pyspark-policy-v1"))
        ),
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "checks": checks,
        "code_sha256": hashlib.sha256(code.encode()).hexdigest(),
        "expected_code_sha256": expected["code_sha256"],
        "execution": "not executed",
    }


@mcp.tool()
def log_skill_validate_report(report: dict[str, Any]) -> dict[str, Any]:
    """Validate one in-memory report against its trusted report contract."""
    if not isinstance(report, dict):
        raise ValueError("report must be an object")
    try:
        encoded = json.dumps(
            report, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
    except (TypeError, ValueError) as exc:
        raise ValueError(f"report must contain only finite JSON values: {exc}") from None
    if len(encoded) > MAX_RESOURCE_BYTES:
        raise ValueError(f"report exceeds {MAX_RESOURCE_BYTES} bytes")
    report_version = report.get("report_contract_version")
    if report_version == "system-event-report-v1":
        workflow_skill = SYSTEM_WORKFLOW_SKILL
        contract_resource = SYSTEM_REPORT_CONTRACT_RESOURCE
        semantic_validator = _system_report_semantic_errors
    elif report_version == "dns-report-v1":
        workflow_skill=DNS_WORKFLOW_SKILL
        contract_resource=DNS_REPORT_CONTRACT_RESOURCE
        semantic_validator=_dns_report_semantic_errors
    elif report_version == "ids-report-v1":
        workflow_skill=IDS_WORKFLOW_SKILL
        contract_resource=IDS_REPORT_CONTRACT_RESOURCE
        semantic_validator=_ids_report_semantic_errors
    elif report_version == "c2-detection-report-v1":
        workflow_skill=C2_DNS_WORKFLOW_SKILL
        contract_resource=C2_DNS_REPORT_CONTRACT_RESOURCE
        semantic_validator=_c2_dns_report_semantic_errors
    elif report_version == "exfiltration-detection-report-v1":
        workflow_skill=EXFIL_WORKFLOW_SKILL
        contract_resource=EXFIL_REPORT_CONTRACT_RESOURCE
        semantic_validator=_exfil_report_semantic_errors
    elif report_version == "lateral-movement-detection-report-v1":
        workflow_skill=LATERAL_WORKFLOW_SKILL
        contract_resource=LATERAL_REPORT_CONTRACT_RESOURCE
        semantic_validator=_lateral_report_semantic_errors
    elif report_version == "security-investigation-report-v1":
        workflow_skill=CORRELATION_WORKFLOW_SKILL
        contract_resource=CORRELATION_REPORT_CONTRACT_RESOURCE
        semantic_validator=_correlation_report_semantic_errors
    elif report_version == "security-investigation-report-v2":
        workflow_skill=CORRELATION_WORKFLOW_SKILL
        contract_resource=PCAP_CORRELATION_REPORT_CONTRACT_RESOURCE
        semantic_validator=_pcap_correlation_report_semantic_errors
    elif report_version == "security-investigation-handoff-v1":
        workflow_skill=HANDOFF_WORKFLOW_SKILL
        contract_resource=HANDOFF_REPORT_CONTRACT_RESOURCE
        semantic_validator=_handoff_report_semantic_errors
    elif report_version == "security-investigation-handoff-v2":
        workflow_skill=HANDOFF_WORKFLOW_SKILL
        contract_resource=PCAP_HANDOFF_REPORT_CONTRACT_RESOURCE
        semantic_validator=_pcap_handoff_report_semantic_errors
    elif report_version in {None, "security-report-v1"}:
        workflow_skill = WORKFLOW_SKILL
        contract_resource = REPORT_CONTRACT_RESOURCE
        semantic_validator = _report_semantic_errors
    else:
        raise ValueError(f"unsupported report_contract_version: {report_version!r}")
    contract = _published_json_resource(workflow_skill, contract_resource)
    schema = contract.get("schema", contract)
    errors = _json_schema_errors(report, schema)
    errors.extend(semantic_validator(report))

    errors = list(dict.fromkeys(errors))
    return {
        "contract": contract.get(
            "$id", contract.get("id", contract.get("version", "security-report-v1"))
        ),
        "valid": not errors,
        "errors": errors,
        "report_sha256": hashlib.sha256(encoded).hexdigest(),
        "execution": "not executed",
    }


@mcp.tool()
def log_skill_resolve(sample: str, vendor: str | None = None, product: str | None = None, log_type: str | None = None) -> dict[str, Any]:
    """Rank approved parsers for one sample using metadata and deterministic parsing."""
    if not sample.strip():
        raise ValueError("sample must not be empty")
    candidates = _resolve(sample, vendor, product, log_type)
    selected = candidates[0] if candidates and candidates[0]["parse_success"] else None
    return {"selected": selected, "candidates": candidates[:10], "unknown_format": selected is None}


@mcp.tool()
def log_skill_validate(skill_name: str) -> dict[str, Any]:
    """Validate published skill frontmatter, parser contracts, and bundled samples."""
    path = _safe_child(SKILLS_DIR, skill_name)
    errors: list[str] = []
    sample_results: list[dict[str, Any]] = []
    try:
        skill = _load_skill(path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return {"skill_name": skill_name, "valid": False, "errors": [str(exc)], "sample_results": []}
    samples_dir = path / "assets" / "samples"
    sample_paths = (
        sorted(samples_dir.glob("*.log"))
        if skill["parsers"] and samples_dir.is_dir()
        else []
    )
    for sample_path in sample_paths:
        try:
            safe_sample = _safe_resource_path(
                path, sample_path.relative_to(path).as_posix()
            )
            sample_text = _read_limited(safe_sample, MAX_SAMPLE_BYTES)
        except (OSError, ValueError) as exc:
            errors.append(f"{sample_path.name}: unsafe sample resource: {exc}")
            continue
        for line_number, line in enumerate(sample_text.splitlines(), 1):
            if not line.strip():
                continue
            accepted = []
            for parser in skill["parsers"]:
                try:
                    _parse_record(parser, line)
                    accepted.append(parser["id"])
                except (ValueError, TypeError, csv.Error):
                    pass
            sample_results.append({"file": sample_path.name, "line": line_number, "accepted_by": accepted})
            if not accepted:
                errors.append(f"{sample_path.name}:{line_number} was not accepted by any parser")
    return {
        "skill_name": skill_name,
        "kind": skill["kind"],
        "valid": not errors,
        "errors": errors,
        "parser_count": len(skill["parsers"]),
        "resource_count": len(skill["resources"]),
        "sample_results": sample_results,
    }


@mcp.tool()
def log_skill_test_parser(skill_name: str, parser_id: str, samples: list[str]) -> dict[str, Any]:
    """Run a deterministic approved parser against up to 100 sample records."""
    if not samples or len(samples) > MAX_TEST_SAMPLES:
        raise ValueError(f"samples must contain 1 to {MAX_TEST_SAMPLES} records")
    parser = _parser_by_id(skill_name, parser_id)
    results = []
    passed = 0
    for index, sample in enumerate(samples):
        try:
            normalized = _parse_record(parser, sample)
            passed += 1
            results.append({"index": index, "ok": True, "normalized": normalized})
        except (ValueError, TypeError, csv.Error) as exc:
            results.append({"index": index, "ok": False, "error": str(exc), "raw_event": sample})
    return {"parser_id": parser_id, "total": len(samples), "passed": passed, "failed": len(samples) - passed, "results": results}


@mcp.tool()
def log_skill_list_drafts() -> dict[str, Any]:
    """List draft skills awaiting human review and Git promotion."""
    DRAFTS_DIR.mkdir(parents=True, exist_ok=True)
    drafts = []
    for path in sorted(
        item
        for item in DRAFTS_DIR.iterdir()
        if item.is_dir() and not item.is_symlink() and NAME_RE.fullmatch(item.name)
    ):
        skill_path = path / "SKILL.md"
        try:
            skill = _parse_skill_markdown(_read_limited(skill_path, MAX_SKILL_BYTES), path.name)
            parser_path = path / "parser.yaml"
            drafts.append({
                "name": skill["name"],
                "description": skill["description"],
                "kind": "parser" if parser_path.is_file() else "workflow",
                "has_parser": parser_path.is_file(),
            })
        except (OSError, ValueError, yaml.YAMLError) as exc:
            drafts.append({"name": path.name, "invalid": True, "error": str(exc)})
    return {"count": len(drafts), "drafts": drafts}


@mcp.tool()
def log_skill_get_draft(skill_name: str) -> dict[str, Any]:
    """Get a draft skill and its optional parser YAML for review."""
    path = _safe_child(DRAFTS_DIR, skill_name)
    skill_markdown = _read_limited(path / "SKILL.md", MAX_SKILL_BYTES)
    parser_path = path / "parser.yaml"
    parser_yaml = _read_limited(parser_path, MAX_PARSER_BYTES) if parser_path.is_file() else None
    return {
        "skill_name": skill_name,
        "kind": "parser" if parser_yaml is not None else "workflow",
        "skill_markdown": skill_markdown,
        "parser_yaml": parser_yaml,
        "sha256": hashlib.sha256((skill_markdown + (parser_yaml or "")).encode()).hexdigest(),
    }


@mcp.tool()
def log_skill_save_draft(
    skill_name: str,
    skill_markdown: str,
    parser_yaml: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Validate and save a parser or parserless draft for later Git review."""
    if len(skill_markdown.encode()) > MAX_SKILL_BYTES or (
        parser_yaml is not None and len(parser_yaml.encode()) > MAX_PARSER_BYTES
    ):
        raise ValueError("draft exceeds size limits")
    _parse_skill_markdown(skill_markdown, skill_name)
    if parser_yaml is not None:
        parser = yaml.safe_load(parser_yaml)
        errors = _validate_parser(parser, skill_name)
        if isinstance(parser, dict) and parser.get("status") != "draft":
            errors.append("draft parser status must be draft")
        if errors:
            raise ValueError("; ".join(errors))
    path = _safe_child(DRAFTS_DIR, skill_name)
    if path.exists() and not overwrite:
        raise FileExistsError("draft already exists; set overwrite=true to replace it")
    path.mkdir(parents=True, exist_ok=True)
    (path / "SKILL.md").write_text(skill_markdown, encoding="utf-8")
    parser_path = path / "parser.yaml"
    if parser_yaml is not None:
        parser_path.write_text(parser_yaml, encoding="utf-8")
    elif parser_path.exists():
        parser_path.unlink()
    digest = hashlib.sha256((skill_markdown + (parser_yaml or "")).encode()).hexdigest()
    return {
        "saved": True,
        "skill_name": skill_name,
        "kind": "parser" if parser_yaml is not None else "workflow",
        "sha256": digest,
        "publication": "not published; promote through Git review",
    }


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
