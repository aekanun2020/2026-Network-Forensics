# Restore NF-01 service after overnight VM stop

- Started UTC: 2026-09-09T04:23:53.384703+00:00
- Actor: Codex / thaimcpagent@gmail.com, configuration bigdatainpractice.
- Target: bigdatainpractice1 / asia-southeast1-a / student-1.
- Authorization: user requested “ทำให้ใช้ได้เหมือนเมื่อคืนนี้ดิ”. Existing public unauthenticated MCP authorization remains in effect.
- Before: VM TERMINATED, e2-standard-8, no guest accelerators, IP 34.142.187.162 still attached, tags http-server and https-server retained.
- Planned: attempt to start the existing VM; inspect existing container and data state after boot, restore only existing NF-01 services if necessary, and verify the real public MCP URL. No new VM, GPU, billing, IAM, firewall, or disk provisioning. Record any denied action accurately; do not broaden privileges.
- Cost: starting resumes normal existing VM CPU/RAM charges; existing disk/IP/network charges apply.
- Cleanup: retain the same lab; user may stop the VM after use. No data deletion.
- Status: restoration in progress.

## Inspection and start outcome

Regional address resource `student-1` in asia-southeast1 is reserved at 34.142.187.162, status IN_USE, attached to the same VM. This confirms the user's manual reservation after the previous session; Codex did not create or alter the reservation.

`gcloud compute instances start student-1 --project=bigdatainpractice1 --zone=asia-southeast1-a --configuration=bigdatainpractice --quiet` returned HTTP 403: missing `compute.instances.start` for account thaimcpagent@gmail.com. No VM state change succeeded. This was a GCP IAM denial, not an automatic approval review rejection. User asked to start student-1 manually with their VM-management account; no IAM expansion requested. Service inspection is pending VM startup.
