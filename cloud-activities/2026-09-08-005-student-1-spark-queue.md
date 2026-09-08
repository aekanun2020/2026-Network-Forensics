# Bound Spark job admission on student-1

- Actor/project/VM: Codex using thaimcpagent@gmail.com; bigdatainpractice1; student-1 in asia-southeast1-a.
- Authorization: user requested continuing the 4-person lab setup with resource limits.
- Before: upstream server launches one driver per submitted job without a global active-job limit.
- Planned change: replace only the new lab MCP server implementation with a real async admission queue; preserve code snapshots, hashes, idempotency and terminal status records. At most 2 active jobs and 8 admitted jobs. Queue-full errors are explicit; cancel works for queued jobs; old queued jobs become INTERRUPTED after restart, without replay.
- Deployment: rebuild/recreate only the newly installed spark-hdfs-mcp service via Compose. No firewall or cloud resource API changes.
- Validation: real MCP test submits four Spark jobs, checks QUEUED/RUNNING states and successful counts. No mock service or external model.
- Status: completed; see recorded results below. Cost: existing VM build and runtime only.
- Recovery: upstream exact blob hashes in platform/nf01/UPSTREAM.json identify the source version; no automatic rollback or deletion of job records.

## Deployment and extra verification

MCP image rebuilt and only its container recreated successfully. Main live test passed four real Spark count jobs. Additional real-server verification will admit 8 Spark jobs with bounded 120-second waits, verify an overflow request is rejected, verify idempotent replay and queued cancellation, then cancel all test jobs in a finally block. This checks scheduling/control behavior; the separate count jobs establish actual data processing. Scripts and transient job/status/log files are written on the existing VM only.

## Result

PASS, 2026-09-08T14:54:54.785649+00:00 to 2026-09-08T14:54:55.435532+00:00. Verified 8-job admission bound, explicit overflow error, replay returning the same job ID, and queued/running cancellation. After cleanup, 0 nonterminal jobs and 12 retained terminal records (4 successful count jobs plus 8 control-test jobs).

- [Complete queue test record](evidence/2026-09-08-queue-verification.json)
- [Deployed file hashes](evidence/2026-09-08-deployment-summary.json)

Restart reconciliation for QUEUED work was implemented but has not yet been exercised by a restart test.

Record finalized UTC: 2026-09-08T14:59:31.287178+00:00
