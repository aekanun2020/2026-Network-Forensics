# NF-01 container platform — public HTTPS MCP verified

Runtime source is pinned in [UPSTREAM.json](UPSTREAM.json). Deployment uses the [original Compose](docker-compose.yml) and [lab override](compose.lab.yml). [HDFS configuration](hadoop/hdfs-site.xml) enables permissions; after import the raw input tree will be owned by root and read-only to the normal spark identity. Simple-auth HDFS is not a security boundary against arbitrary submitted code that impersonates other users. Public HTTPS is enabled at https://34-142-187-162.sslip.io/mcp. The user explicitly confirmed unauthenticated public access and waived per-person isolation; the shared access model remains in place.

## Operator files

- [Source inventory](UPSTREAM.json)
- [Lab resource and log limits](compose.lab.yml)
- [MCP server](mcp-server/server.py)
- [Evidence tools](mcp-server/evidence_tools.py)
- [Canonical question and six input hashes](../../cases/01-investigate-10.70.0.66/QUESTION.md)
- [Cloud activity records](../../cloud-activities/README.md)

Run `sudo docker compose -f docker-compose.yml -f compose.lab.yml up -d --build` from the installation directory. The base and lab Compose files publish only to 127.0.0.1. The HTTPS override publishes TCP 80/443 and routes only MCP requests to the real server. No GCP firewall changes are performed by these files. Skills MCP runs with an empty catalog until an in-scope catalog is selected; no reference answers, other datasets or attack-specific skills are staged.

The service uses shared access without login, as explicitly requested. Per-user authenticated workspaces are not implemented. Spark admission is bounded to 2 active jobs and 8 total admitted jobs; queued work is marked INTERRUPTED after server restart and is never silently replayed. Four simultaneous external SDK sessions have passed; Claude Desktop account setup still requires the learner-side check below.

- [Six-file evidence inventory](evidence-inventory.json)
- [Administrator import script](import_evidence.py)
- [Live integration checks](verify_live.py)

## Verified on student-1

8 containers healthy. Six raw files verified through real MCP. Four concurrent SDK sessions and four Spark count jobs passed, with at most 2 jobs RUNNING. Queue-full, idempotent replay, and cancellation tests passed. See [recorded results](../../cloud-activities/evidence/2026-09-08-deployment-summary.json). Disk observed after the main test: 7.6 GiB used / 89 GiB available. This is not a Claude Desktop test.

- [Queue control test](verify_queue.py)

## Public HTTPS and learner connection

**Endpoint:** `https://34-142-187-162.sslip.io/mcp`

- [Claude Desktop connection guide](CLAUDE-DESKTOP.md)
- [Public MCP test script](verify_public.py)
- [Initial public TLS/MCP verification evidence — 8 September](../../cloud-activities/evidence/2026-09-08-public-mcp-verification.json)
- [Verification after VM restart — 9 September](../../cloud-activities/evidence/2026-09-09-public-mcp-verification.json)
- [HTTPS Compose override with pinned Caddy image](compose.https.yml)
- [TLS ingress configuration](Caddyfile)
- [HTTPS preparation and consent record](../../cloud-activities/2026-09-08-006-student-1-https.md)
- [Successful start and external verification record](../../cloud-activities/2026-09-08-007-student-1-public-verification.md)

On 2026-09-08 the user saved `http-server` and `https-server` VM tags. Codex verified those tags, then started only the prepared HTTPS service. No GCP firewall or tags were modified by Codex. The original eight backend containers remained healthy and the ninth container, Caddy, serves HTTPS on the existing VM.

The certificate was issued by Let's Encrypt. The operator Mac verified TLS 1.3 with normal trust and hostname validation and then used the real MCP SDK over the public endpoint. All six file sizes/SHA-256 values, one text record, one PCAP packet, four concurrent sessions and one Spark count job passed. The job returned 100000 rows. No model was called. This is not a Claude Desktop account test; use the learner guide to complete that check.

The endpoint forwards the original Streamable HTTP transport without protocol conversion. Spark/HDFS UI and skills ports retain their loopback bindings. Authentication and per-person isolation were explicitly waived by the user; reachable callers share tool access, including Spark code submission.

To start the same service, use `sudo docker compose -f docker-compose.yml -f compose.lab.yml -f compose.https.yml up -d --no-deps https` in `/opt/nf01`. Caddy retains its certificate/account data in its named volumes. Do not copy private certificate keys or account material into this repository.

The hostname uses external sslip.io DNS. On 2026-09-09, Codex verified the user's manual reservation: regional address `student-1` in `asia-southeast1` holds `34.142.187.162` and is attached to this VM. Retain that address resource and attachment to preserve the URL across VM stops. See the [restore record](../../cloud-activities/2026-09-09-001-student-1-restore.md). This deployment does not purchase a domain or a commercial certificate and does not create an additional VM or cloud load balancer. Existing GCP resource and network charges still apply.

For repeat verification, run `verify_public.py --host VERIFIED_VM_HOSTNAME --output /path/to/new-audit.json` with the real MCP SDK installed. Choose a new file; the script refuses to overwrite an existing audit. The default output uses a UTC timestamp.

Three user-created clones (`student-2`, `student-3`, `student-4`) now have their own HTTPS configuration and TLS storage. See the [group endpoint directory](GROUP-ENDPOINTS.md) for per-VM URLs and verification outcomes, and the [clone activity record](../../cloud-activities/2026-09-09-002-configure-cloned-labs.md) for changes. The original student-1 was not modified.
