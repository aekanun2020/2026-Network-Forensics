# NF-01 container platform — internal installation verified; learner access pending

Runtime source is pinned in [UPSTREAM.json](UPSTREAM.json). Deployment uses the [original Compose](docker-compose.yml) and [lab override](compose.lab.yml). [HDFS configuration](hadoop/hdfs-site.xml) enables permissions; after import the raw input tree will be owned by root and read-only to the normal spark identity. Simple-auth HDFS is not a security boundary against arbitrary submitted code that impersonates other users. Public learner access remains disabled; the user has waived login and per-person isolation, but HTTPS startup is awaiting the specific public-exposure confirmation requested by automatic approval review and the user-managed firewall step.

## Operator files

- [Source inventory](UPSTREAM.json)
- [Lab resource and log limits](compose.lab.yml)
- [MCP server](mcp-server/server.py)
- [Evidence tools](mcp-server/evidence_tools.py)
- [Canonical question and six input hashes](../../cases/01-investigate-10.70.0.66/QUESTION.md)
- [Cloud activity records](../../cloud-activities/README.md)

Run `sudo docker compose -f docker-compose.yml -f compose.lab.yml up -d --build` from the installation directory. The base and lab Compose files publish only to 127.0.0.1. The separately staged HTTPS override is not running. No GCP firewall changes are performed by these files. Skills MCP runs with an empty catalog until an in-scope catalog is selected; no reference answers, other datasets or attack-specific skills are staged.

Initial installation is an administrator-only environment. Per-user authenticated workspaces are not yet implemented. Spark admission is bounded to 2 active jobs and 8 total admitted jobs; queued work is marked INTERRUPTED after server restart and is never silently replayed. Do not distribute this endpoint as a ready four-user lab.

- [Six-file evidence inventory](evidence-inventory.json)
- [Administrator import script](import_evidence.py)
- [Live integration checks](verify_live.py)

## Verified on student-1

8 containers healthy. Six raw files verified through real MCP. Four concurrent SDK sessions and four Spark count jobs passed, with at most 2 jobs RUNNING. Queue-full, idempotent replay, and cancellation tests passed. See [recorded results](../../cloud-activities/evidence/2026-09-08-deployment-summary.json). Disk observed after the main test: 7.6 GiB used / 89 GiB available. This is not a Claude Desktop test.

- [Queue control test](verify_queue.py)

## Learner connection decision

On 2026-09-08 the user selected HTTPS for Claude Desktop and then explicitly waived login and per-person isolation. The shared Spark identity, workspace access and job submission remain as implemented; no isolation is claimed.

The prepared endpoint hostname is `34-142-187-162.sslip.io`, verified by DNS to resolve to the VM external IP `34.142.187.162`. The intended URL is `https://34-142-187-162.sslip.io/mcp`, **not yet operational or certified**. The user owns no domain; this configuration depends on external sslip.io DNS and the current VM IP, which has not been established as reserved.

- [HTTPS Compose override with pinned Caddy image](compose.https.yml)
- [TLS ingress configuration](Caddyfile)
- [HTTPS activity record and approval blocker](../../cloud-activities/2026-09-08-006-student-1-https.md)

The Caddy configuration passed real validation with networking disabled and no published ports. Automatic approval review blocked the command to install/start public HTTPS because unauthenticated callers could read evidence and submit Spark code. A specific confirmation of those public capabilities was requested. No HTTPS container was started and no certificate was issued. The user must also add `http-server` and `https-server` network tags to `student-1`; the verified existing rules allow TCP 80 and 443 from `0.0.0.0/0` for these tags. Codex has not modified firewall rules or tags.

After the pending confirmation and network step, deploy only the HTTPS service, verify a trusted certificate and real public MCP calls, and test Claude Desktop before declaring learner access verified. Public HTTPS without login gives every reachable caller shared tool access, including Spark execution. The configuration forwards the original Streamable HTTP transport without protocol conversion; Spark/HDFS UI and skills ports retain their loopback bindings.
