# Configure user-created NF-01 clones

- Started UTC: 2026-09-09T06:15:48.462513+00:00
- Actor: Codex / thaimcpagent@gmail.com, existing OS Login/IAP access.
- Project / zone: bigdatainpractice1 / asia-southeast1-a.
- Authorization: user requested configuration of three machine-image clones and supplied a screenshot showing student-2, student-3 and student-4. Target names verified by GCP inventory. Original student-1 remains in use and must not be modified.
- Verified targets: [{"name": "student-2", "ip": "34.177.83.99"}, {"name": "student-3", "ip": "34.142.220.235"}, {"name": "student-4", "ip": "35.240.216.66"}]. All RUNNING, e2-standard-8, no guest accelerators, tags http-server and https-server. Only student-1 has a reserved address in current inventory; new addresses are not shown as reserved.
- Difference from source: all three clones have the default Compute Engine service account 65900660028-compute@developer.gserviceaccount.com attached with storage-read/logging/monitoring/service/trace scopes; student-1 has no attached service account. Assess access implications before enabling public clone endpoints. Do not silently grant IAM or expose cloud credentials through the lab.
- Planned actions: SSH read-only inspection of each clone (existing OS Login public key may be registered/renewed by gcloud), verify copied runtime/data, prepare per-VM Caddy hostname and fresh independent TLS account/certificate volumes. Preserve HDFS Docker project/volume identity and raw evidence. Recreate only each clone's HTTPS service after prerequisites are established; test real external MCP with six hashes and a uniquely named bounded Spark count job on each. No model calls.
- Boundaries: no student-1 mutation, no GPU, no VM/disk creation or resizing, no paid-account activation, no GCP VPC firewall or tag changes by Codex. User owns manual infrastructure changes.
- Cost: existing user-created VM/IP/disk/network charges plus small local TLS storage and test workloads. No certificate/domain purchases.
- Cleanup: retain all raw evidence and copied history; do not delete cloned source certificate/account volumes. New TLS volumes are specific to each clone.
- Status: inspection/preparation; new public endpoints not yet configured or verified.

## Access blocker verified

All three gcloud IAP SSH attempts reached the SSH server but failed with `Permission denied (publickey)` (exit 255). Each VM had a new host identity, and gcloud added its public host key to the local known-hosts file. No guest command ran. OS Login is TRUE on all three VMs. A direct IAM testIamPermissions call using the current operator's token privately in memory returned `{}` for `iam.serviceAccounts.actAs` on the attached service account. Tokens were not printed or stored in the project.

Project IAM inspection found the attached default service account has roles/editor, roles/datafusion.runner and roles/dataproc.worker. The existing storage/logging/monitoring/service/trace OAuth scopes also apply; this is not a claim that every Editor capability is usable through the VM token. The source VM has no attached service account. OS Login's documented service-account permission requirement is supported by [Google's SSH access documentation](https://docs.cloud.google.com/compute/docs/connect/ssh-best-practices/login-access).

User asked to stop only student-2, student-3 and student-4, edit each attached Service account to None/No service account, save, and start them again. Do not stop or modify student-1. This matches the source deployment without broadening the operator's IAM. The new IPs are not yet reserved; inspect their actual values again after the user's stop/start before writing hostname-specific configs. No clone endpoint URL has been advertised as operational.

No VM guest configuration, raw data, firewall, IAM binding, service account attachment or reservation was changed by Codex. New deployment remains pending SSH access.
