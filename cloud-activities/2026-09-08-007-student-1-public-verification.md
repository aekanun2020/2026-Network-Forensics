# Start HTTPS and verify public MCP

- Started UTC: 2026-09-08T15:19:22.388313+00:00
- Actor: Codex / thaimcpagent@gmail.com using OS Login sudo.
- Project / VM / zone: bigdatainpractice1 / student-1 / asia-southeast1-a.
- User action verified: user saved tags and asked to continue. GCP read confirms http-server and https-server tags on RUNNING student-1 with external IP 34.142.187.162. These are user changes, not Codex firewall/tag mutations.
- Authorization: explicit public unauthenticated read and shared Spark execution confirmation retained from previous turn.
- Planned actions: start only the prepared https service with the pinned Caddy image and corrected spark-network; obtain a real Let's Encrypt certificate; verify trusted TLS and real MCP over the public URL from outside the VM. If Spark verification creates a job, use a uniquely named deterministic counting job with no external model calls; retain the test record. Do not modify raw evidence, other services, firewall, IAM, GPU, billing, or VM sizing.
- Cost: existing VM, IP, disk and network usage; no purchased domain/certificate or new cloud load balancer/VM. Certificate and request logs use existing disk.
- Cleanup: retain HTTPS service and certificate volume for lab operation; retain audit/test records; no broad pruning.
- Status: public HTTPS and real external MCP verification passed; learner Claude Desktop connection not yet tested.

## Certificate and initial external check

HTTPS service started successfully. Caddy completed real HTTP-01 validation and logged certificate obtained successfully from Let's Encrypt. A direct external `curl` request to the HTTPS root returned HTTP/2 200 using normal trust verification; no `-k` or certificate bypass. All 8 backend containers remained healthy, plus the running HTTPS container. Real external MCP verification is running in an isolated local MCP SDK 1.30.0 environment and records its full outcome separately. Planned final guest mutation: copy updated operator README and learner connection guide to /opt/nf01 after verification; no evidence-file changes.

## External verification result

[Recorded results](evidence/2026-09-08-public-mcp-verification.json): PASS from 2026-09-08T15:20:56.383562+00:00 to 2026-09-08T15:21:52.899046+00:00. Real MCP SDK 1.30.0 from the operator Mac outside GCP, no tunnel, no certificate bypass and no model calls. TLS 1.3 with trusted hostname validation; issuer Let's Encrypt YE2, certificate expiry 2026-12-07 14:21:03 UTC. The test called 15 tools in the main session plus 4 concurrent hash tool calls in separate sessions. All six hashes and sizes matched the canonical inventory; text/PCAP reads passed; Spark job `5e2f8aa0-d0a5-472a-8528-3282f7598ab8` SUCCEEDED with `NF01_ROWS=100000`. The test created one uniquely named verification script and job record; no raw evidence write was requested.

This establishes public protocol/data/job functionality, not an end-to-end test within a learner's Claude Desktop account. The connection guide tells users to add the connector and verify a real file stat/hash before starting the case.

Updated operator README and Claude Desktop connection guide installed under /opt/nf01 with mode 0644. Final service inventory: HTTPS running and all 8 backend containers healthy. Finalized 2026-09-08T15:23:53.305591+00:00.
