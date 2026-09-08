# student-1: OS Login and installation preflight

- Started: 2026-09-08T21:38:18.393776+07:00
- Actor: Codex using `thaimcpagent@gmail.com`
- GCP project: `bigdatainpractice1`
- VM / zone: `student-1` / `asia-southeast1-a`
- Authorization: user instructed “ทำต่อสิ” after manually creating, configuring, and starting the VM.
- Before: RUNNING, e2-standard-8, 100 GiB pd-standard, OS Login TRUE, no service account, no GPU. IAP port 22 reached; no authenticated SSH yet.
- Planned change: gcloud OS Login may register the existing local public SSH key (private key is never copied). Establish SSH, then run read-only OS, disk, sudo, and container inventory checks.
- Command: `gcloud compute ssh student-1 --tunnel-through-iap --zone=asia-southeast1-a --project=bigdatainpractice1 --configuration=bigdatainpractice --command=<read-only inventory>`.
- Scope: no firewall/IAM role edits, no VM lifecycle operations. User's manual changes above are observations, not Codex actions.
- Cost: existing running VM continues its normal charges; no new compute/storage resources planned for this step.
- Status: completed; see recorded result below.
- Cleanup: close SSH; any uploaded public-key registration can be removed after lab administration ends. Do not delete shared SSH keys without checking other uses.

## Result (2026-09-08T14:39:41.752600+00:00)

SSH via OS Login/IAP succeeded; `sudo -n true` succeeded. Ubuntu 26.04.1 LTS; root filesystem 96 GiB, 1.8 GiB used, 95 GiB available; RAM 31 GiB. Docker absent. Only SSH and local DNS listening. gcloud accepted the VM host key locally; no remote application changes. Public-key registration may have occurred through gcloud; no operation ID was returned.

Record finalized UTC: 2026-09-08T14:59:31.286817+00:00
