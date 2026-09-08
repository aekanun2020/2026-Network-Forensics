# Verify student-1 through real MCP

- Actor: Codex using thaimcpagent@gmail.com / OS Login; project bigdatainpractice1, VM student-1, asia-southeast1-a.
- Authorization: continue installation and test before learner use.
- Planned operations: upload and execute platform/nf01/verify_live.py using the installed MCP SDK; actual initialize/list tools, six file stats/hashes, bounded record and packet reads, four concurrent sessions, and four small Spark count jobs reading canonical F3. No model API calls.
- Mutations: four saved Python jobs, immutable snapshots, Spark job statuses/logs, transient Spark shuffle/cache, and verification JSON. No modifications to raw evidence or GCP firewall.
- Before: stack started; evidence import underway. Test starts only after successful import.
- Status: completed; see recorded results below.
- Cost: existing VM compute and disk use; no new GCP resources.
- Cleanup: retain logs and result as operator evidence; clear only known test jobs after review if requested.

## Result

PASS, 2026-09-08T14:50:57.248406+00:00 to 2026-09-08T14:52:32.024105+00:00. 96 real MCP calls; all six file SHA-256/length checks passed; five line reads and one actual PCAP packet read passed. Four concurrent hash-reading sessions passed. Four real Spark jobs each counted 100000 F3 rows successfully. Queue state observed; maximum RUNNING jobs observed was 2. No model calls.

- [Complete MCP record](evidence/2026-09-08-mcp-verification.json)
- [Deployment and disk observations](evidence/2026-09-08-deployment-summary.json)

This is an administrator-side SDK integration test, not a Claude Desktop end-to-end test or a proof of per-user isolation.

Record finalized UTC: 2026-09-08T14:59:31.287107+00:00
