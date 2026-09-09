# Restore NF-01 service after overnight VM stop

- Started UTC: 2026-09-09T04:23:53.384703+00:00
- Actor: Codex / thaimcpagent@gmail.com, configuration bigdatainpractice.
- Target: bigdatainpractice1 / asia-southeast1-a / student-1.
- Authorization: user requested “ทำให้ใช้ได้เหมือนเมื่อคืนนี้ดิ”. Existing public unauthenticated MCP authorization remains in effect.
- Before: VM TERMINATED, e2-standard-8, no guest accelerators, IP 34.142.187.162 still attached, tags http-server and https-server retained.
- Planned: attempt to start the existing VM; inspect existing container and data state after boot, restore only existing NF-01 services if necessary, and verify the real public MCP URL. No new VM, GPU, billing, IAM, firewall, or disk provisioning. Record any denied action accurately; do not broaden privileges.
- Cost: starting resumes normal existing VM CPU/RAM charges; existing disk/IP/network charges apply.
- Cleanup: retain the same lab; user may stop the VM after use. No data deletion.
- Status: service restored automatically after user VM start; real external MCP checks passed.

## Inspection and start outcome

Regional address resource `student-1` in asia-southeast1 is reserved at 34.142.187.162, status IN_USE, attached to the same VM. This confirms the user's manual reservation after the previous session; Codex did not create or alter the reservation.

`gcloud compute instances start student-1 --project=bigdatainpractice1 --zone=asia-southeast1-a --configuration=bigdatainpractice --quiet` returned HTTP 403: missing `compute.instances.start` for account thaimcpagent@gmail.com. No VM state change succeeded. This was a GCP IAM denial, not an automatic approval review rejection. User asked to start student-1 manually with their VM-management account; no IAM expansion requested. Service inspection is pending VM startup.

## User-started VM and resumed checks

At 2026-09-09T04:27:12.241021+00:00, after the user said they started the VM, GCP read confirmed RUNNING at static IP 34.142.187.162 with both HTTP/HTTPS tags retained. Initial external HTTPS probe could not connect to TCP 443; inspecting guest/container startup before making changes. Planned verification may create one uniquely named Spark count job via the real MCP, with no model calls or raw evidence changes. Today's results will be saved separately from yesterday's verification.

## Automatic service recovery

Serial console showed Docker restoring the existing containers during boot, and cloud-init completed around 42 seconds after startup. The initial connection refusal was observed before the web containers were ready. A subsequent inspection showed all 8 backend containers healthy and the HTTPS container running, without any Codex start/restart/rebuild command. A normal external HTTPS request returned HTTP/2 200. Caddy loaded the retained certificate/account volume. The absence of an attached VM service account caused the startup script runner's cloud-logging flush warning; no startup script was configured, and this did not prevent the lab containers from becoming healthy. No IAM/service-account change was made.

The verification script was updated locally to accept an output path and reject an existing output file, preserving yesterday's evidence. Running the same real public MCP checks with today's new audit path; the test's uniquely named Spark count script/job is the only intended application write for this check.

## Final verification

[Today's new audit](evidence/2026-09-09-public-mcp-verification.json) is PASS from 2026-09-09T04:28:19.488601+00:00 to 2026-09-09T04:29:43.405534+00:00. Trusted public TLS validation passed, and the certificate SHA-256 is unchanged from yesterday. The real MCP SDK verified all six canonical file sizes/hashes, a text record and a PCAP packet, four concurrent sessions, and Spark job `5bc22531-08f2-42c0-aeab-58837a199ca3` with result SUCCEEDED and `NF01_ROWS=100000`. There were 17 main-session tool calls plus four concurrent hash calls. Model calls: 0. Yesterday's audit is unchanged.

The VM was started manually by the user; Docker restored all nine containers automatically. Codex did not change GCP IAM, firewall, tags, VM sizing, disks, addresses or container configuration during this recovery. The verification created one uniquely named job script and persistent job/output records via the existing MCP. URL remains `https://34-142-187-162.sslip.io/mcp`. This new check uses the MCP SDK; the user separately reported successful Claude Desktop testing the previous night.

Finalized 2026-09-09T04:29:59.799320+00:00.
