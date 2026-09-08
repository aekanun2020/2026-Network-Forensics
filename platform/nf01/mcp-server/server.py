from __future__ import annotations

import ast
import asyncio
import hashlib
import json
import os
import re
import signal
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError


SPARK_MASTER = os.getenv("SPARK_MASTER_URL", "spark://spark-master:7077")
SPARK_UI = os.getenv("SPARK_MASTER_UI_URL", "http://spark-master:8080").rstrip("/")
HDFS_UI = os.getenv("HDFS_NAMENODE_URL", "http://namenode:9870").rstrip("/")
HDFS_ROOT = PurePosixPath(os.getenv("HDFS_ROOT", "/mcp"))
JOBS_DIR = Path(os.getenv("JOBS_DIR", "/opt/spark-apps")).resolve()
STATE_DIR = Path(os.getenv("JOB_STATE_DIR", "/var/lib/spark-hdfs-mcp")).resolve()
IMPORTS_DIR = Path(os.getenv("IMPORTS_DIR", "/imports")).resolve()
SPARK_SUBMIT = os.getenv("SPARK_SUBMIT", "/opt/spark/bin/spark-submit")

MAX_CODE_BYTES = 512 * 1024
MAX_TEXT_BYTES = 4 * 1024 * 1024
MAX_LOG_LINES = 2_000
FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.py$")
IMPORT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$")
IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
MEMORY_RE = re.compile(r"^(\d+)([mMgG])$")
ALLOWED_CONF = {
    "spark.app.name",
    "spark.cores.max",
    "spark.default.parallelism",
    "spark.driver.memory",
    "spark.executor.cores",
    "spark.executor.instances",
    "spark.executor.memory",
    "spark.sql.adaptive.enabled",
    "spark.sql.shuffle.partitions",
}

mcp = FastMCP(
    "Spark and HDFS",
    instructions=(
        "Use spark_save_job then spark_validate_job before spark_submit_job. "
        "Use spark_read_job and spark_replace_job_text for small, auditable repairs. "
        "Poll spark_job_status and inspect spark_job_logs on failure. HDFS tools accept "
        "virtual paths relative to the restricted /mcp root, such as /lab/input.log, "
        "and return physical HDFS paths such as /mcp/lab/input.log. Pass the returned "
        "physical path unchanged to Spark; never pass the original virtual path to "
        "Spark or pass a returned /mcp path back to an HDFS tool. Spark files and "
        "settings are allowlisted. Never "
        "assume a submitted job succeeded until its status is SUCCEEDED. "
        "Jobs first enter QUEUED; at most two execute concurrently and eight are admitted. "
        "Poll status while queued; do not resubmit duplicate work."
    ),
    host="0.0.0.0",
    port=8000,
    json_response=True,
)


@dataclass
class RunningJob:
    process: asyncio.subprocess.Process
    log_path: Path
    collector: asyncio.Task[None] | None = None


running_jobs: dict[str, RunningJob] = {}
submit_lock = asyncio.Lock()
MAX_ACTIVE_JOBS = 2
MAX_ADMITTED_JOBS = 8
job_slots = asyncio.Semaphore(MAX_ACTIVE_JOBS)
queued_tasks: dict[str, asyncio.Task[None]] = {}
BOOT_ID = str(uuid.uuid4())


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def job_file(filename: str) -> Path:
    if not FILENAME_RE.fullmatch(filename):
        raise ToolError("filename must be a plain .py filename with safe characters")
    path = (JOBS_DIR / filename).resolve()
    if path.parent != JOBS_DIR:
        raise ToolError("job must be directly inside the jobs directory")
    return path


def safe_hdfs_path(path: str) -> str:
    relative = PurePosixPath("/" + path.lstrip("/"))
    if ".." in relative.parts:
        raise ToolError("HDFS path cannot contain '..'")
    resolved = HDFS_ROOT.joinpath(*relative.parts[1:])
    if resolved != HDFS_ROOT and HDFS_ROOT not in resolved.parents:
        raise ToolError("HDFS path escapes the configured root")
    return str(resolved)


def validate_memory(value: str, maximum_mb: int) -> None:
    match = MEMORY_RE.fullmatch(value)
    if not match:
        raise ToolError("memory must look like 512m, 1g, or 2g")
    amount = int(match.group(1)) * (1024 if match.group(2).lower() == "g" else 1)
    if not 256 <= amount <= maximum_mb:
        raise ToolError(f"memory must be between 256m and {maximum_mb}m")


def clean_conf(conf: dict[str, str]) -> dict[str, str]:
    unknown = sorted(set(conf) - ALLOWED_CONF)
    if unknown:
        raise ToolError("unsupported Spark configuration: " + ", ".join(unknown))
    result = {str(key): str(value) for key, value in conf.items()}
    limits = {
        "spark.cores.max": (1, 2),
        "spark.default.parallelism": (1, 256),
        "spark.executor.cores": (1, 2),
        "spark.executor.instances": (1, 2),
        "spark.sql.shuffle.partitions": (1, 512),
    }
    for key, (minimum, maximum) in limits.items():
        if key not in result:
            continue
        try:
            value = int(result[key])
        except ValueError as exc:
            raise ToolError(f"{key} must be an integer") from exc
        if not minimum <= value <= maximum:
            raise ToolError(f"{key} must be between {minimum} and {maximum}")
    if "spark.driver.memory" in result:
        validate_memory(result["spark.driver.memory"], 4096)
    if "spark.executor.memory" in result:
        validate_memory(result["spark.executor.memory"], 1024)
    if result.get("spark.sql.adaptive.enabled", "true").lower() not in {"true", "false"}:
        raise ToolError("spark.sql.adaptive.enabled must be true or false")
    return result


async def webhdfs(
    method: str,
    path: str,
    operation: str,
    params: dict[str, str] | None = None,
    content: bytes | None = None,
) -> httpx.Response:
    query = {"op": operation, "user.name": "spark"}
    query.update(params or {})
    url = f"{HDFS_UI}/webhdfs/v1{quote(safe_hdfs_path(path), safe='/')}"
    async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
        response = await client.request(method, url, params=query, content=content)
    if response.is_error:
        try:
            message = response.json()["RemoteException"]["message"]
        except (ValueError, KeyError, TypeError):
            message = response.text[:1_000]
        raise ToolError(f"HDFS {operation} failed ({response.status_code}): {message}")
    return response


def status_path(job_id: str) -> Path:
    try:
        uuid.UUID(job_id)
    except ValueError as exc:
        raise ToolError("invalid job_id") from exc
    return STATE_DIR / f"{job_id}.json"


def read_status(job_id: str) -> dict[str, Any]:
    path = status_path(job_id)
    if not path.is_file():
        raise ToolError(f"unknown job_id: {job_id}")
    return json.loads(path.read_text(encoding="utf-8"))


def write_status(job_id: str, status: dict[str, Any]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    path = status_path(job_id)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(status, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def request_sha256(
    filename: str,
    arguments: list[str],
    settings: dict[str, str],
    code_sha256: str,
) -> str:
    payload = json.dumps(
        {
            "filename": filename,
            "arguments": arguments,
            "conf": settings,
            "code_sha256": code_sha256,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return sha256_bytes(payload)


def statuses_for_idempotency_key(idempotency_key: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in STATE_DIR.glob("*.json"):
        try:
            status = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            continue
        if status.get("idempotency_key") == idempotency_key:
            records.append(status)
    return records


def reconcile_interrupted_jobs() -> int:
    """Mark work owned by an earlier server process terminal without replaying it."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    reconciled = 0
    for path in STATE_DIR.glob("*.json"):
        try:
            status = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            continue
        if status.get("status") not in {"QUEUED", "STARTING", "RUNNING"}:
            continue
        if status.get("boot_id") == BOOT_ID:
            continue
        job_id = status.get("job_id")
        try:
            uuid.UUID(str(job_id))
        except ValueError:
            continue
        status.update(
            status="INTERRUPTED",
            finished_at=now(),
            exit_code=None,
            reconciled_by_boot_id=BOOT_ID,
            interruption_reason="MCP server restarted before a terminal status was recorded",
        )
        write_status(str(job_id), status)
        reconciled += 1
    return reconciled


async def stop_launched_process(process: asyncio.subprocess.Process) -> None:
    """Best-effort termination for a process whose durable launch did not complete."""
    if process.returncode is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        await asyncio.wait_for(process.communicate(), timeout=10)
        return
    except asyncio.TimeoutError:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    await process.communicate()


async def fs_shell(*arguments: str) -> tuple[int, bytes]:
    process = await asyncio.create_subprocess_exec(
        "/opt/spark/bin/spark-class",
        "org.apache.hadoop.fs.FsShell",
        *arguments,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    output, _ = await process.communicate()
    return process.returncode or 0, output


async def hdfs_path_exists(path: str) -> bool:
    return_code, output = await fs_shell("-test", "-e", path)
    if return_code == 0:
        return True
    if return_code == 1:
        return False
    raise ToolError(output.decode("utf-8", errors="replace")[-2_000:])


async def hdfs_is_file(path: str) -> bool:
    return_code, output = await fs_shell("-test", "-f", path)
    if return_code == 0:
        return True
    if return_code == 1:
        return False
    raise ToolError(output.decode("utf-8", errors="replace")[-2_000:])


async def hdfs_move(source: str, destination: str) -> None:
    return_code, output = await fs_shell("-mv", source, destination)
    if return_code != 0:
        raise ToolError(output.decode("utf-8", errors="replace")[-2_000:])


async def hdfs_remove_if_exists(path: str) -> None:
    await fs_shell("-rm", "-f", path)


async def hdfs_file_fingerprint(path: str) -> dict[str, Any]:
    """Stream exact HDFS bytes through the MCP process without buffering the file."""
    process = await asyncio.create_subprocess_exec(
        "/opt/spark/bin/spark-class",
        "org.apache.hadoop.fs.FsShell",
        "-cat",
        path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    stderr_task = asyncio.create_task(process.stderr.read())
    digest = hashlib.sha256()
    length = 0
    while chunk := await process.stdout.read(1024 * 1024):
        digest.update(chunk)
        length += len(chunk)
    return_code = await process.wait()
    error = await stderr_task
    if return_code != 0:
        raise ToolError(error.decode("utf-8", errors="replace")[-2_000:])
    return {"bytes": length, "sha256": digest.hexdigest()}


def file_fingerprint(path: Path) -> dict[str, Any]:
    """Hash one stable regular file and return fields safe to compare after a copy."""
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("source is not a regular file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    after = path.stat()
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_identity != after_identity:
        raise ValueError("source changed while it was being hashed")
    return {
        "device": after.st_dev,
        "inode": after.st_ino,
        "size": after.st_size,
        "mtime_ns": after.st_mtime_ns,
        "ctime_ns": after.st_ctime_ns,
        "sha256": digest.hexdigest(),
    }


async def collect_output(job_id: str) -> None:
    job = running_jobs[job_id]
    assert job.process.stdout is not None
    with job.log_path.open("ab") as output:
        async for chunk in job.process.stdout:
            output.write(chunk)
            output.flush()
    return_code = await job.process.wait()
    status = read_status(job_id)
    status.update(
        status="SUCCEEDED" if return_code == 0 else "FAILED",
        exit_code=return_code,
        finished_at=now(),
    )
    write_status(job_id, status)
    running_jobs.pop(job_id, None)


@mcp.tool()
def spark_save_job(filename: str, code: str, overwrite: bool = False) -> dict[str, Any]:
    """Save a syntactically valid UTF-8 PySpark application."""
    path = job_file(filename)
    data = code.encode("utf-8")
    if len(data) > MAX_CODE_BYTES:
        raise ToolError(f"code exceeds {MAX_CODE_BYTES} bytes")
    try:
        ast.parse(code, filename=filename)
    except SyntaxError as exc:
        raise ToolError(f"syntax error line {exc.lineno}: {exc.msg}") from exc
    if path.exists() and not overwrite:
        raise ToolError("job exists; set overwrite=true to replace it")
    path.write_bytes(data)
    return {
        "filename": filename,
        "bytes": len(data),
        "sha256": sha256_bytes(data),
        "saved": True,
    }


@mcp.tool()
def spark_read_job(filename: str) -> dict[str, Any]:
    """Read a bounded saved PySpark application before making a targeted repair."""
    path = job_file(filename)
    if not path.is_file():
        raise ToolError(f"job does not exist: {filename}")
    data = path.read_bytes()
    if len(data) > MAX_CODE_BYTES:
        raise ToolError(f"job exceeds {MAX_CODE_BYTES} bytes")
    return {"filename": filename, "bytes": len(data), "code": data.decode("utf-8")}


@mcp.tool()
def spark_replace_job_text(
    filename: str,
    old_text: str,
    new_text: str,
    expected_occurrences: int = 1,
) -> dict[str, Any]:
    """Replace exact text in one saved job and reject ambiguous or invalid repairs."""
    if not old_text:
        raise ToolError("old_text cannot be empty")
    if not 1 <= expected_occurrences <= 20:
        raise ToolError("expected_occurrences must be between 1 and 20")
    path = job_file(filename)
    if not path.is_file():
        raise ToolError(f"job does not exist: {filename}")
    code = path.read_text(encoding="utf-8")
    occurrences = code.count(old_text)
    if occurrences != expected_occurrences:
        raise ToolError(
            f"expected {expected_occurrences} occurrence(s), found {occurrences}; read the job and narrow old_text"
        )
    updated = code.replace(old_text, new_text)
    data = updated.encode("utf-8")
    if len(data) > MAX_CODE_BYTES:
        raise ToolError(f"updated code exceeds {MAX_CODE_BYTES} bytes")
    try:
        ast.parse(updated, filename=filename)
    except SyntaxError as exc:
        raise ToolError(f"replacement creates syntax error line {exc.lineno}: {exc.msg}") from exc
    path.write_bytes(data)
    return {
        "filename": filename,
        "replacements": occurrences,
        "bytes": len(data),
        "valid_python": True,
    }


@mcp.tool()
def spark_validate_job(filename: str) -> dict[str, Any]:
    """Parse a saved Spark job and report whether it imports PySpark."""
    path = job_file(filename)
    if not path.is_file():
        raise ToolError(f"job does not exist: {filename}")
    code = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(code, filename=filename)
    except SyntaxError as exc:
        raise ToolError(f"syntax error line {exc.lineno}: {exc.msg}") from exc
    imports_pyspark = any(
        (isinstance(node, ast.Import) and any(a.name.startswith("pyspark") for a in node.names))
        or (isinstance(node, ast.ImportFrom) and (node.module or "").startswith("pyspark"))
        for node in ast.walk(tree)
    )
    return {"filename": filename, "valid_python": True, "imports_pyspark": imports_pyspark}


@mcp.tool()
async def spark_submit_job(
    filename: str,
    arguments: list[str] | None = None,
    conf: dict[str, str] | None = None,
    expected_sha256: str | None = None,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    """Submit one immutable snapshot with single-process persistent replay safety.

    HDFS arguments must use the physical path returned by an HDFS tool, for example
    ``/mcp/lab/input.log``, or the equivalent full URI
    ``hdfs://namenode:9000/mcp/lab/input.log``. Never pass an HDFS MCP virtual path
    such as ``/lab/input.log`` to Spark.

    An idempotency key requires the trusted caller's expected code hash. Durable
    reservations make replays safe across restarts, but the asyncio lock does not
    coordinate multiple MCP server replicas. Snapshots and terminal state are
    intentionally retained for audit.
    """
    path = job_file(filename)
    arguments = arguments or []
    if len(arguments) > 32 or any(len(arg) > 1_024 for arg in arguments):
        raise ToolError("at most 32 arguments of 1024 characters are allowed")
    if expected_sha256 is not None and not SHA256_RE.fullmatch(expected_sha256):
        raise ToolError("expected_sha256 must be a 64-character hexadecimal SHA-256")
    if idempotency_key is not None and not IDEMPOTENCY_KEY_RE.fullmatch(idempotency_key):
        raise ToolError(
            "idempotency_key must be 1..128 safe characters: letters, digits, '.', '_', ':', or '-'"
        )
    if idempotency_key is not None and expected_sha256 is None:
        raise ToolError("expected_sha256 is required when idempotency_key is provided")
    expected_code_hash = expected_sha256.lower() if expected_sha256 is not None else None
    settings = clean_conf(conf or {})
    settings.setdefault("spark.cores.max", "2")
    settings.setdefault("spark.executor.cores", "1")
    settings.setdefault("spark.executor.memory", "512m")
    settings["spark.driver.host"] = "spark-hdfs-mcp"

    async with submit_lock:
        request_hash = (
            request_sha256(filename, arguments, settings, expected_code_hash)
            if idempotency_key is not None and expected_code_hash is not None
            else None
        )
        if idempotency_key is not None:
            existing = await asyncio.to_thread(
                statuses_for_idempotency_key, idempotency_key
            )
            if existing:
                mismatched = [
                    item
                    for item in existing
                    if item.get("request_sha256") != request_hash
                ]
                if mismatched:
                    raise ToolError(
                        "idempotency_key was already used for a different Spark request"
                    )
                selected = max(
                    existing,
                    key=lambda item: str(item.get("started_at", "")),
                )
                return {**selected, "deduplicated": True}

        try:
            code = await asyncio.to_thread(path.read_bytes)
        except OSError as exc:
            raise ToolError(f"job does not exist or cannot be read: {filename}") from exc
        if len(code) > MAX_CODE_BYTES:
            raise ToolError(f"job exceeds {MAX_CODE_BYTES} bytes")
        code_hash = sha256_bytes(code)
        if expected_code_hash is not None and code_hash != expected_code_hash:
            raise ToolError(
                f"saved job SHA-256 mismatch: expected {expected_code_hash}, found {code_hash}"
            )
        if request_hash is None:
            request_hash = request_sha256(filename, arguments, settings, code_hash)

        if len(queued_tasks) >= MAX_ADMITTED_JOBS:
            raise ToolError("Spark admission queue is full (8 jobs); retry after a job finishes")

        job_id = str(uuid.uuid4())
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        snapshot = STATE_DIR / f"{job_id}.job.py"
        status = {
            "job_id": job_id,
            "application": filename,
            "code_snapshot": snapshot.name,
            "code_sha256": code_hash,
            "request_sha256": request_hash,
            "idempotency_key": idempotency_key,
            "boot_id": BOOT_ID,
            "status": "QUEUED",
            "pid": None,
            "started_at": now(),
            "finished_at": None,
            "exit_code": None,
        }
        write_status(job_id, status)
        try:
            await asyncio.to_thread(snapshot.write_bytes, code)
            await asyncio.to_thread(snapshot.chmod, 0o444)
        except Exception as exc:
            status.update(status="LAUNCH_FAILED", finished_at=now(), launch_error=str(exc)[:2000])
            write_status(job_id, status)
            return {**status, "deduplicated": False}
        task = asyncio.create_task(launch_queued_job(job_id, snapshot, arguments, settings))
        queued_tasks[job_id] = task
        task.add_done_callback(lambda _task: queued_tasks.pop(job_id, None))
        return {**status, "deduplicated": False}


async def launch_queued_job(job_id, snapshot, arguments, settings):
    """Hold an admission slot for the lifetime of the real spark-submit process."""
    process = None
    try:
        async with job_slots:
            status = read_status(job_id)
            status.update(status="STARTING", launched_at=now())
            write_status(job_id, status)
            command = [SPARK_SUBMIT, "--master", SPARK_MASTER, "--deploy-mode", "client"]
            for key, value in sorted(settings.items()):
                command.extend(["--conf", f"{key}={value}"])
            command.extend([str(snapshot), *arguments])
            process = await asyncio.create_subprocess_exec(
                *command, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT, start_new_session=True,
            )
            status.update(status="RUNNING", pid=process.pid)
            write_status(job_id, status)
            job = RunningJob(process=process, log_path=STATE_DIR / f"{job_id}.log")
            running_jobs[job_id] = job
            job.collector = asyncio.create_task(collect_output(job_id))
            await job.collector
    except BaseException as exc:
        if process is not None:
            try:
                await stop_launched_process(process)
            except (OSError, RuntimeError):
                pass
        running_jobs.pop(job_id, None)
        status = read_status(job_id)
        status.update(
            status="CANCELLED" if isinstance(exc, asyncio.CancelledError) else "LAUNCH_FAILED",
            finished_at=now(), exit_code=process.returncode if process else None,
            launch_error=f"{type(exc).__name__}: {exc}"[:2000],
        )
        write_status(job_id, status)



@mcp.tool()
def spark_job_status(job_id: str) -> dict[str, Any]:
    """Return durable status for a submitted job."""
    return read_status(job_id)


@mcp.tool()
def spark_job_logs(job_id: str, tail_lines: int = 200) -> dict[str, Any]:
    """Return combined stdout/stderr from a submitted job."""
    read_status(job_id)
    if not 1 <= tail_lines <= MAX_LOG_LINES:
        raise ToolError(f"tail_lines must be 1..{MAX_LOG_LINES}")
    path = STATE_DIR / f"{job_id}.log"
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines() if path.exists() else []
    return {"job_id": job_id, "lines": lines[-tail_lines:]}


@mcp.tool()
async def spark_cancel_job(job_id: str) -> dict[str, Any]:
    """Cancel a running Spark job submitted by this server process."""
    job = running_jobs.get(job_id)
    if job is None and job_id in queued_tasks:
        task = queued_tasks[job_id]
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        status = read_status(job_id)
        status.update(status="CANCELLED", finished_at=now())
        write_status(job_id, status)
        return status
    if job is None:
        status = read_status(job_id)
        if status["status"] != "RUNNING":
            return status
        raise ToolError("running job is detached after server restart and cannot be cancelled")
    os.killpg(job.process.pid, signal.SIGTERM)
    try:
        await asyncio.wait_for(job.process.wait(), timeout=10)
    except asyncio.TimeoutError:
        os.killpg(job.process.pid, signal.SIGKILL)
        await job.process.wait()
    assert job.collector is not None
    await job.collector
    status = read_status(job_id)
    status.update(status="CANCELLED", finished_at=now())
    write_status(job_id, status)
    return status


@mcp.tool()
def spark_list_jobs(limit: int = 20) -> list[dict[str, Any]]:
    """List recent MCP-submitted jobs."""
    if not 1 <= limit <= 100:
        raise ToolError("limit must be 1..100")
    records = []
    for path in STATE_DIR.glob("*.json"):
        try:
            records.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass
    return sorted(records, key=lambda item: item.get("started_at", ""), reverse=True)[:limit]


@mcp.tool()
async def spark_cluster_status() -> dict[str, Any]:
    """Return Spark master capacity, applications, and registered workers."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(f"{SPARK_UI}/json/")
        response.raise_for_status()
    data = response.json()
    return {
        "url": data.get("url"),
        "status": data.get("status"),
        "cores": data.get("cores"),
        "cores_used": data.get("coresused"),
        "memory": data.get("memory"),
        "memory_used": data.get("memoryused"),
        "workers": data.get("workers", []),
        "active_apps": data.get("activeapps", []),
    }


@mcp.tool()
async def hdfs_list(path: str = "/") -> list[dict[str, Any]]:
    """List by virtual path below /mcp; do not include the /mcp prefix."""
    response = await webhdfs("GET", path, "LISTSTATUS")
    return response.json()["FileStatuses"]["FileStatus"]


@mcp.tool()
async def hdfs_stat(path: str) -> dict[str, Any]:
    """Get metadata by virtual path below /mcp; do not include the /mcp prefix."""
    response = await webhdfs("GET", path, "GETFILESTATUS")
    return response.json()["FileStatus"]


@mcp.tool()
async def hdfs_mkdir(path: str) -> dict[str, Any]:
    """Create by virtual path below /mcp; the result returns its physical path."""
    response = await webhdfs("PUT", path, "MKDIRS")
    return {"path": safe_hdfs_path(path), "created": response.json()["boolean"]}


@mcp.tool()
async def hdfs_write_text(
    path: str, text: str, overwrite: bool = False, replication: int = 2
) -> dict[str, Any]:
    """Write by virtual path below /mcp; the result returns its physical path."""
    content = text.encode("utf-8")
    if len(content) > MAX_TEXT_BYTES:
        raise ToolError(f"text exceeds {MAX_TEXT_BYTES} bytes")
    if replication not in {1, 2}:
        raise ToolError("replication must be 1 or 2")
    await webhdfs(
        "PUT",
        path,
        "CREATE",
        {"overwrite": str(overwrite).lower(), "replication": str(replication)},
        content,
    )
    return {"path": safe_hdfs_path(path), "bytes": len(content), "replication": replication}


@mcp.tool()
async def hdfs_read_text(path: str, max_bytes: int = 1_048_576) -> dict[str, Any]:
    """Read by virtual path below /mcp; do not include the /mcp prefix."""
    if not 1 <= max_bytes <= MAX_TEXT_BYTES:
        raise ToolError(f"max_bytes must be 1..{MAX_TEXT_BYTES}")
    status = await hdfs_stat(path)
    if status["type"] != "FILE" or status["length"] > max_bytes:
        raise ToolError("path is not a file or exceeds max_bytes")
    response = await webhdfs("GET", path, "OPEN")
    try:
        text = response.content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ToolError("file is not UTF-8 text") from exc
    return {"path": safe_hdfs_path(path), "bytes": len(response.content), "text": text}


@mcp.tool()
async def hdfs_delete(path: str, recursive: bool = False) -> dict[str, Any]:
    """Delete by virtual path below /mcp; deleting the root itself is forbidden."""
    absolute = safe_hdfs_path(path)
    if PurePosixPath(absolute) == HDFS_ROOT:
        raise ToolError("deleting the HDFS root is forbidden")
    response = await webhdfs("DELETE", path, "DELETE", {"recursive": str(recursive).lower()})
    return {"path": absolute, "deleted": response.json()["boolean"]}


@mcp.tool()
async def hdfs_import_file(
    source_name: str, destination: str, overwrite: bool = False
) -> dict[str, Any]:
    """Verify a stable import in HDFS before publishing it with an atomic rename.

    ``destination`` is an HDFS MCP virtual path such as ``/lab/input.log``; do not
    include the ``/mcp`` prefix. The returned ``destination`` is the physical HDFS
    path, such as ``/mcp/lab/input.log``. Pass that returned value unchanged to
    PySpark or ``spark_submit_job``. Do not pass it back into an HDFS MCP tool.

    Callers must serialize writes to one destination. An existing destination is
    replay-safe when ``overwrite`` is false and its exact bytes already match the
    stable source. Otherwise an existing destination is moved to a temporary
    backup for rollback because FsShell rename does not provide a cross-replica
    compare-and-swap operation.
    """
    if not IMPORT_NAME_RE.fullmatch(source_name):
        raise ToolError("source_name must be a plain filename with safe characters")
    source = (IMPORTS_DIR / source_name).resolve()
    if source.parent != IMPORTS_DIR:
        raise ToolError(f"import file does not exist: {source_name}")
    try:
        source_before = await asyncio.to_thread(file_fingerprint, source)
    except (OSError, ValueError) as exc:
        raise ToolError(f"import source is unavailable or unstable: {exc}") from exc
    target = safe_hdfs_path(destination)
    target_path = PurePosixPath(target)
    if target_path == HDFS_ROOT:
        raise ToolError("destination must be a file below the restricted HDFS root")

    # A caller may lose the first successful response after the atomic publish.
    # Treat an exact source/destination match as the same request so retrying
    # with overwrite=false recovers the proof instead of forcing an unsafe
    # overwrite. Different content still fails closed.
    if not overwrite and await hdfs_path_exists(target):
        if not await hdfs_is_file(target):
            raise ToolError("destination exists and is not a file")
        destination_fingerprint = await hdfs_file_fingerprint(target)
        try:
            source_after = await asyncio.to_thread(file_fingerprint, source)
        except (OSError, ValueError) as exc:
            raise ToolError(f"import source changed during replay verification: {exc}") from exc
        if source_before != source_after:
            raise ToolError("import source changed during replay verification")
        if (
            destination_fingerprint["bytes"] != source_before["size"]
            or destination_fingerprint["sha256"] != source_before["sha256"]
        ):
            raise ToolError(
                "destination exists with content different from the stable import source"
            )
        return {
            "source_name": source_name,
            "destination": target,
            "bytes": destination_fingerprint["bytes"],
            "sha256": destination_fingerprint["sha256"],
            "destination_bytes": destination_fingerprint["bytes"],
            "destination_sha256": destination_fingerprint["sha256"],
            "destination_verified": True,
            "source_stable": True,
            "overwrite": False,
            "reused": True,
        }

    parent = str(target_path.parent)
    token = uuid.uuid4().hex
    temporary = str(parent / PurePosixPath(f".{target_path.name}.import-{token}.tmp"))
    backup = str(parent / PurePosixPath(f".{target_path.name}.backup-{token}.tmp"))

    mkdir_code, mkdir_output = await fs_shell("-mkdir", "-p", parent)
    if mkdir_code != 0:
        raise ToolError(mkdir_output.decode("utf-8", errors="replace")[-2_000:])

    temporary_may_exist = False
    backup_exists = False
    published = False
    try:
        temporary_may_exist = True
        copy_code, copy_output = await fs_shell("-put", str(source), temporary)
        if copy_code != 0:
            raise ToolError(copy_output.decode("utf-8", errors="replace")[-2_000:])

        try:
            source_after = await asyncio.to_thread(file_fingerprint, source)
        except (OSError, ValueError) as exc:
            raise ToolError(f"import source changed during copy: {exc}") from exc
        if source_before != source_after:
            raise ToolError(
                "import source changed during copy; temporary HDFS data is rejected"
            )

        destination_fingerprint = await hdfs_file_fingerprint(temporary)
        if (
            destination_fingerprint["bytes"] != source_before["size"]
            or destination_fingerprint["sha256"] != source_before["sha256"]
        ):
            raise ToolError(
                "temporary HDFS content differs from the stable import source"
            )

        target_exists = await hdfs_path_exists(target)
        if target_exists:
            if not overwrite:
                raise ToolError("destination exists; set overwrite=true to replace it")
            if not await hdfs_is_file(target):
                raise ToolError("destination exists and is not a file")
            await hdfs_move(target, backup)
            backup_exists = True

        try:
            await hdfs_move(temporary, target)
            temporary_may_exist = False
            published = True
        except BaseException:
            if backup_exists and not await hdfs_path_exists(target):
                await hdfs_move(backup, target)
                backup_exists = False
            raise

        if backup_exists:
            await hdfs_remove_if_exists(backup)
            backup_exists = False

        return {
            "source_name": source_name,
            "destination": target,
            "bytes": destination_fingerprint["bytes"],
            "sha256": destination_fingerprint["sha256"],
            "destination_bytes": destination_fingerprint["bytes"],
            "destination_sha256": destination_fingerprint["sha256"],
            "destination_verified": True,
            "source_stable": True,
            "overwrite": overwrite,
            "reused": False,
        }
    finally:
        if temporary_may_exist:
            await hdfs_remove_if_exists(temporary)
        if backup_exists:
            target_present = False
            try:
                target_present = await hdfs_path_exists(target)
            except ToolError:
                pass
            if not published and not target_present:
                try:
                    await hdfs_move(backup, target)
                    backup_exists = False
                except ToolError:
                    pass
            # Never delete the only known copy of the previous destination.
            if backup_exists and (published or target_present):
                await hdfs_remove_if_exists(backup)


@mcp.tool()
async def hdfs_cluster_status() -> dict[str, Any]:
    """Return HDFS capacity, block health, and DataNode counts."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            f"{HDFS_UI}/jmx", params={"qry": "Hadoop:service=NameNode,name=FSNamesystem"}
        )
        response.raise_for_status()
    bean = response.json()["beans"][0]
    keys = [
        "CapacityTotal", "CapacityUsed", "CapacityRemaining", "FilesTotal",
        "BlocksTotal", "MissingBlocks", "NumLiveDataNodes", "NumDeadDataNodes",
        "UnderReplicatedBlocks",
    ]
    return {key: bean.get(key) for key in keys}


from evidence_tools import register_evidence_tools

register_evidence_tools(mcp, hdfs_stat, safe_hdfs_path, HDFS_UI, hdfs_file_fingerprint)

if __name__ == "__main__":
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    reconcile_interrupted_jobs()
    mcp.run(transport="streamable-http")
