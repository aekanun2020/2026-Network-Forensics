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
- Status: all three clone endpoints configured and real public MCP verification passed; learner Claude Desktop account checks remain user-side.

## Access blocker verified

All three gcloud IAP SSH attempts reached the SSH server but failed with `Permission denied (publickey)` (exit 255). Each VM had a new host identity, and gcloud added its public host key to the local known-hosts file. No guest command ran. OS Login is TRUE on all three VMs. A direct IAM testIamPermissions call using the current operator's token privately in memory returned `{}` for `iam.serviceAccounts.actAs` on the attached service account. Tokens were not printed or stored in the project.

Project IAM inspection found the attached default service account has roles/editor, roles/datafusion.runner and roles/dataproc.worker. The existing storage/logging/monitoring/service/trace OAuth scopes also apply; this is not a claim that every Editor capability is usable through the VM token. The source VM has no attached service account. OS Login's documented service-account permission requirement is supported by [Google's SSH access documentation](https://docs.cloud.google.com/compute/docs/connect/ssh-best-practices/login-access).

User asked to stop only student-2, student-3 and student-4, edit each attached Service account to None/No service account, save, and start them again. Do not stop or modify student-1. This matches the source deployment without broadening the operator's IAM. The new IPs are not yet reserved; inspect their actual values again after the user's stop/start before writing hostname-specific configs. No clone endpoint URL has been advertised as operational.

No VM guest configuration, raw data, firewall, IAM binding, service account attachment or reservation was changed by Codex. New deployment remains pending SSH access.

## User correction and configuration preparation

User reported completion of the service-account change. GCP inventory confirms all three RUNNING without attached service accounts and with HTTP/HTTPS tags intact. Actual IP mapping after restart changed: student-2 = 34.142.220.235, student-3 = 34.177.83.99, student-4 = 35.240.216.66. DNS resolution verified for each IP-based sslip.io hostname. SSH and sudo succeeded on all three. The copied server.py SHA-256 is 1634b597824dd473fd2c7ec049c388614d0e4f3a300382788cb1471a38e2420c and hdfs-site.xml SHA-256 is 144016d19c6d08d35710c04366c39deb76199b0c4ccbb7a36bab8634d125c0fb on every clone, matching the tested source. Their existing HTTPS service still had the source hostname before the change.

Prepared per-VM files under platform/nf01/instances/. Deployment will copy those two files to each clone's /tmp, retain the copied source configuration as /opt/nf01/Caddyfile.source-20260909 and compose.https.yml.source-20260909 when not already present, install new configs, validate Caddy and Compose, then recreate only https. New volumes are https-student-N-data and https-student-N-config within the unchanged nf01-group1 Compose project. The copied source certificate/account volumes are retained but not mounted by the new HTTPS service. No certificate private keys are read/exported. No HDFS project/volume names or raw inputs change. All mutations run sequentially per target and never target student-1.

## HTTPS deployment outcome

Sequential deployment completed successfully on student-2, student-3 and student-4. Each retained source config copies, installed its two per-VM files, passed real Caddy/Compose validation, created fresh per-VM TLS data/config volumes, and recreated only the HTTPS service. All eight backend containers on every clone remained healthy. Each new hostname returned HTTP 200 from an external curl request with normal certificate trust verification; no bypass flags were used. Reservation inventory still contains only student-1; new IPs are not reserved as of this check.

Next, run the real public MCP verification separately on each new hostname and preserve per-VM dated JSON results. These tests create one unique Spark count script/job per VM and never write the six raw inputs. No commands target student-1.

Read-only Docker inspection confirms each HTTPS service mounts only its own new https-student-N-data/config volumes and its per-VM Caddyfile. Deployed Caddyfile/Compose SHA-256 values match the repository files and are recorded in the instance manifest. All 24 backend containers (8 per clone) were healthy at this inspection. Planned final guest-file changes: replace copied operator/Claude connection guides on the three new VMs with their correct per-VM endpoint documentation after tests; source VM remains untouched.

## Per-clone public MCP results

All three passed trusted TLS, six exact sizes/SHA-256 values, a text record, a PCAP packet, four concurrent sessions, and one Spark count job returning 100000 rows. All four certificate fingerprints (source plus three clones) are distinct; each clone certificate matches its own hostname. Each new test job ID is unique. No model calls.

- student-2: PASS, 18 main-session tool calls plus 4 concurrent hash calls; job `76615594-c7b8-4d38-acdf-ccea7350d5d8`; completed 2026-09-09T06:27:25.801408+00:00.
- student-3: PASS, 17 main-session tool calls plus 4 concurrent hash calls; job `ba541d70-11ea-4084-8412-fb17506c200d`; completed 2026-09-09T06:29:02.005194+00:00.
- student-4: PASS, 17 main-session tool calls plus 4 concurrent hash calls; job `b152a26a-1dea-4cf2-b5fd-2ef487d70ea9`; completed 2026-09-09T06:30:34.889450+00:00.

See the historical group endpoint directory (`platform/nf01/GROUP-ENDPOINTS.md`, removed from the current repository on 2026-09-10) for the full mapping and linked raw verification records. Student-1 was not modified or retested by this clone deployment; its earlier verification remains separate. Copied source job histories and raw data were retained.

Per-VM README and Claude Desktop guides installed successfully at /opt/nf01 on all three clones, mode 0644. Final inventories showed HTTPS running plus all eight backend containers healthy on each. No guest operations targeted student-1. Finalized 2026-09-09T06:31:39.095474+00:00.
