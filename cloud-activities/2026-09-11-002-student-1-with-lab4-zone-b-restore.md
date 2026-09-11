# Restore recreated lab4 VM in zone b

- Started: 2026-09-11T09:56:03.731552+07:00
- Project: bigdatainpractice1; zone: asia-southeast1-b; VM: student-1-with-lab4.
- Actor: Codex via gcloud configuration bigdatainpractice, account to reconfirm.
- Authorization: user supplied the exact new VM console URL and said “เสร็จล่ะ” after explicitly requesting Codex continue configuration once creation completed. User deleted the previous zone-a VM and created this VM; Codex did neither.
- Before: RUNNING, e2-standard-8, no guestAccelerators returned; external IP 34.21.207.108 (same as previous VM), internal IP 10.148.0.34.
- Planned: inspect real guest/container/config/evidence via OS Login/IAP (may register/refresh operator public SSH key). If hostname is stale, preserve config backup, validate and replace only the HTTPS hostname; recreate only HTTPS if necessary with existing volumes. Verify trusted public TLS, native MCP, six canonical full-file sizes/hashes, psexec-hunt and its packet readability, tool inventory, four concurrent sessions and one unique Spark count job. Test writes only normal uniquely named Spark job/status/output, never raw evidence. Read-only internal checks may help isolate public failures; do not count them as public success.
- Scope: no VM lifecycle, GPU, IAM roles, firewall, reserved IP, billing activation, new managed services, evidence modification or protected local source changes.
- Cost: existing running VM/disk/network charges; small verification CPU/storage/network/log usage. Exact incremental charge unknown.
- Rollback: preserve guest configuration and named data/TLS volumes; restore config if validation fails. Correct current hostname may remain configured if external DNS blocks issuance.
- Status: inspection pending.

## Inspection (2026-09-11T02:56:43.022345+00:00)

Account confirmed thaimcpagent@gmail.com. SSH via OS Login/IAP succeeded; new VM host key recorded locally. All eight backend containers healthy. Root disk 7.8 GiB used and 89 GiB available. MCP source SHA-256 51e8981556a8ab6656d89e6f2220081a93243b8de65ec81ecab0b6ceb3b1b62c matches prior binary-upload implementation. Caddyfile still uses 35-186-155-169.sslip.io.

Next: create exclusive candidate file /opt/nf01/Caddyfile.candidate-zone-b-20260911, validate with existing pinned Caddy image in a transient network-disabled container, back up current Caddyfile with UTC timestamp, replace only hostname and recreate HTTPS only; retain original HDFS/TLS volumes. Certificate issuance is pending and may write Caddy TLS state.

## HTTPS update completed (2026-09-11T02:57:26.544739+00:00)

Caddy and Compose configuration validation passed. Backup /opt/nf01/Caddyfile.before-zone-b-20260911T025652Z; candidate retained as planned. Deployed Caddyfile SHA-256 54bc7e609a0ef5956fbec78736ae6a0f28fa54436f924d32e8e85b41039c9e34. Only HTTPS recreated; all eight backend containers remained healthy with unchanged uptime. Trusted public certificate verification pending.

## Trusted HTTPS reachable (2026-09-11T02:58:12.493141+00:00)

External curl with default certificate/hostname validation succeeded at TLS and reached an HTTP 406 response from /mcp (curl did not supply MCP Accept headers). This is transport reachability, not yet successful MCP protocol verification. Full native SDK tests are now running, including the planned unique Spark job; psexec public verification and independent internal checks are also in progress. No certificate validation bypass. The prior DNS issue was observed on the old VM; no causal claim that changing zone resolved it.

## Verification passed (2026-09-11T09:59:46.346738+07:00)

Endpoint: **https://34-21-207-108.sslip.io/mcp** on the newly created zone-b VM.

[Trusted public TLS and native MCP verification](evidence/2026-09-11-zone-b-public-verification.json): PASS. TLS trust and hostname validation succeeded without bypass. Certificate SHA-256 295467ba95c8ef70ed1e1f937f6ce5c415ced0cd5d32aaf6ea40bd561dadac75. All six canonical complete-file byte counts and hashes matched; text record and PCAP packet read passed; four concurrent independent native SDK sessions passed. Spark job ab66deb1-9fd6-4db6-880e-032a53e4411e SUCCEEDED with NF01_ROWS=100000. Test finished 2026-09-11T02:59:18.969019+00:00. The test created its unique script and normal job/code snapshot/status/log artifacts. No raw evidence modifications.

[Public psexec verification](evidence/2026-09-11-zone-b-psexec-public-verification.json): PASS. hdfs_stat, hdfs_sha256 and hdfs_pcap_packets returned successfully through the actual public HTTPS endpoint. Original capture is 10027488 bytes with SHA-256 85c1ded1fea23cb9277604f7b26a520718eed47445e4624182beb88c2388357f. All 24 native tools remain registered, including hdfs_upload_file. Binary upload was not re-exercised in this restore; availability and unchanged server source were checked.

[Independent internal verification](evidence/2026-09-11-zone-b-internal-verification.json) also passed 9 checks for all seven evidence files and packet readability. It is separate from the external pass and is not used as a substitute for it.

[Caddy certificate issuance events](evidence/2026-09-11-zone-b-tls-issuance.json) confirm authorization finalized and certificate obtained successfully. No changed issuer, DNS provider, protocol, trust settings or firewall was required. The previous failure and DNS inconsistency remain historical observations; these results do not prove that changing VM zone caused recovery.

These are real SDK/client checks, not a test inside a learner's Claude Desktop account. To connect, set the connector URL to the endpoint above. Old URLs with 35-186-155-169 or 34-142-187-162 refer to prior addresses.

The earlier heartbeat remains PAUSED; no need to resume the previous wait-for-readiness check now that readiness was directly verified. No VM start/stop/create/delete, IAM role, firewall, billing activation, GPU or IP reservation was performed by Codex in this restore. Existing VM/disk/network billing continues. Backup and candidate guest paths above are retained for rollback/audit.

Status: COMPLETED. Final read-only check found all eight backend containers healthy and HTTPS running. Caddyfile and MCP source hashes match the values recorded above. Only HTTPS uptime changed; backend services and evidence were retained.
