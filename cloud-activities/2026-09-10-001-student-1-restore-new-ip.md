# Restore student-1 at its current IP

- Started: 2026-09-10T15:21:40.949026+07:00
- Project: bigdatainpractice1; zone: asia-southeast1-a; VM: student-1.
- Actor: Codex using thaimcpagent@gmail.com, configuration bigdatainpractice.
- Authorization: user requested “ตอนนี้รัน student-1 ขึ้นมาแล้ว ช่วยทำให้ใช้งานได้เหมือนเดิม”. User started/recreated the VM; Codex did not. Prior authorization for public HTTPS MCP without per-user login applies to restoration of the same lab.
- Verified before: RUNNING, e2-standard-8, 100 GiB disk, current public IP 35.186.155.169; no guestAccelerators or serviceAccounts in instance response; HTTP/HTTPS tags retained. Prior endpoint used 34.142.187.162.
- Planned: inspect existing containers/config/data via OS Login/IAP; gcloud may register the existing operator public SSH key (private key never copied). Back up affected configuration in VM before updating HTTPS hostname to 35-186-155-169.sslip.io; restore only necessary existing lab services. Validate native MCP, all six canonical sizes/SHA-256 hashes, record/packet reads, four concurrent SDK sessions, and one uniquely named Spark count job. The verification writes a job script/status/output to the existing lab.
- Scope: no new VM, GPU, paid-account activation, IAM role edits, firewall changes or reserved-IP creation. Protected local source untouched.
- Cost: existing running VM/disk/IP charges continue; verification adds small CPU/network/log usage. No separately paid certificate or new compute resources planned.
- Rollback: preserve original guest config; restore it if configuration validation fails. Do not delete evidence or existing job history.
- Status: COMPLETED; service restored and real external verification passed.

## Inspection (2026-09-10T15:22:15.412990+07:00)

OS Login/IAP SSH and sudo succeeded. gcloud added the new VM host public key to local known hosts; any public-key registration is not returned as a separate operation ID. All eight backend containers are healthy and HTTPS is running automatically after the user VM start. Guest Caddyfile still routes hostname 34-142-187-162.sslip.io. Root disk: 7.7 GiB used / 89 GiB available. No backend repair indicated.

Next mutation: upload the corrected Caddyfile, validate with the existing pinned Caddy image in a transient container with networking disabled, preserve original Caddyfile at /opt/nf01/Caddyfile.before-20260910, install corrected config, and recreate only the HTTPS container. Retain existing named TLS and HDFS volumes. Caddy may obtain a new certificate for 35-186-155-169.sslip.io. Update endpoint documentation after verification.

## HTTPS configuration result (2026-09-10T15:22:54.973711+07:00)

Upload, offline Caddy validation, original-config backup and install succeeded. Compose validation succeeded; only nf01-group1-https-1 was recreated. All eight backend containers remained healthy with unchanged uptime. Guest Caddyfile SHA-256: c00459e90908b9c4328754bba446254c680e1b36d39aff3743bb35100733ed6d. Backup: /opt/nf01/Caddyfile.before-20260910. Existing TLS volumes retained. Status: configured, external verification pending.

## Repository reconciliation (2026-09-10T15:24:00.669338+07:00)

Remote main cb702179bc1d9fad5a5b5efa8269fb0958fca0bf intentionally removed platform/nf01. Preserve those removals: publish only the new activity record, verification evidence and navigation on a worktree of latest main. The deployed Caddyfile change is recorded by hash and backup location; do not reintroduce the removed platform source or learner installation guides. The integration verifier used is the historical real SDK script at commit 1b6a05c873a13b0af2586f1b2119a61efe378626, with --host and --output overrides for this run.

## Final verification (2026-09-10T15:25:04.567023+07:00)

Endpoint: **https://35-186-155-169.sslip.io/mcp**. Update the existing Claude Desktop connector URL to this address.

[Real external verification](evidence/2026-09-10-student-1-public-mcp-verification.json) is PASS. Started 2026-09-10T08:23:13.999853+00:00; completed 2026-09-10T08:24:23.249747+00:00. Trusted TLS hostname/certificate validation passed; certificate SHA-256: bae32ff623784644cab8414a4d65138797554fd4cb2ad6d7541825e6eac6edb3. All six canonical byte sizes and SHA-256 hashes matched. One text record and one PCAP packet were read; four concurrent independent MCP sessions passed. Spark job `ecd4cb81-c50c-4ea9-817e-1ac18da55e09` succeeded with `NF01_ROWS=100000`. 16 main-session calls; no model calls. This is MCP SDK verification, not a test inside a learner's Claude Desktop account.

After verification, all eight backend containers remained healthy. Only Caddy was recreated; no Spark/HDFS backend configuration or evidence files were changed. The test added one uniquely named Spark script and its normal job/status/output records. No VM start/stop, IAM role, firewall, disk or public-IP reservation was performed by Codex.

Read-only address lookup found no reserved address matching 35.186.155.169. The hostname depends on the current public IP; a future Stop/Start may require another endpoint update. Existing VM and associated storage/network charges continue.

Guest rollback configuration remains at `/opt/nf01/Caddyfile.before-20260910`; restoring its old hostname would not preserve current endpoint access. The removed platform directory stays removed from current remote main; this record documents the operative URL.
