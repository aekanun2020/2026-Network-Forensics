# Install container runtime on student-1

- Started UTC: 2026-09-08T14:39:41.752764+00:00
- Actor: Codex / thaimcpagent@gmail.com, remote OS user thaimcpagent_gmail_com with sudo.
- Project / VM / zone: bigdatainpractice1 / student-1 / asia-southeast1-a.
- Authorization: user “ทำต่อสิ” to continue installing Docker/MCP.
- Before: Docker absent; Ubuntu 26.04.1; /opt empty; root filesystem 95 GiB free.
- Planned actions: refresh Ubuntu package indexes; inspect and install real distro Docker/Compose packages, enable Docker, then stage the pinned NF-01 runtime under /opt/nf01. Docker may create its host bridge/NAT rules; no GCP VPC firewall rules will be changed. No existing containers are present.
- Commands and outcomes: recorded below as executed.
- Cost: package/image downloads and existing VM operation; no new GCP compute/disk resources.
- Cleanup: retain evidence/results; remove only this newly installed stack and its containers when user requests lab teardown. No global prune.
- Status: completed; see recorded results below.

## Runtime installation result

`apt-get update -qq` succeeded. Installed `docker.io` 29.1.3-0ubuntu4.1 and `docker-compose-v2` 2.40.3+ds1-0ubuntu1 from Ubuntu repositories; 27 new packages, 104 MB download, 432 MB additional package space reported. `systemctl enable --now docker` succeeded. Verified Docker server 29.1.3 and Compose 2.40.3. No previous containers existed.

## Next staged change

Copy verified source bundle to `/opt/nf01`; create bind directories, build images, and start 8 services via `docker compose -f docker-compose.yml -f compose.lab.yml up -d --build`. Explicit per-service CPU/RAM/PID limits and Docker log rotation; all published ports remain loopback. Enable HDFS permission checks. Skills catalog initially empty; learner endpoint not exposed.

## Stack result

All 8 containers reported healthy. Post-build filesystem measurement: 96 GiB total, 7.1 GiB used, 89 GiB available before final HDFS import. This measurement is installation-only, not long-term workload growth.

Record finalized UTC: 2026-09-08T14:59:31.286957+00:00
