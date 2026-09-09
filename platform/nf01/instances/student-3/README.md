# NF-01 lab — student-3

MCP endpoint: `https://34-177-83-99.sslip.io/mcp`

This VM has its own HDFS data and Spark queue. Shared unauthenticated tool access is configured as requested. The Compose project stays `nf01-group1` to preserve copied HDFS volumes; identical Docker names on different VMs are intentional.

- [Caddy configuration](Caddyfile)
- [HTTPS Compose override](compose.https.yml)
- [Claude Desktop setup](CLAUDE-DESKTOP.md)
- [Canonical question](https://github.com/aekanun2020/2026-Network-Forensics/blob/main/cases/01-investigate-10.70.0.66/QUESTION.md)
- [Group endpoint directory and verification](https://github.com/aekanun2020/2026-Network-Forensics/blob/main/platform/nf01/GROUP-ENDPOINTS.md)
- [Cloud activity record](https://github.com/aekanun2020/2026-Network-Forensics/blob/main/cloud-activities/2026-09-09-002-configure-cloned-labs.md)

Runtime directory: `/opt/nf01`. HTTPS uses fresh `student-3` TLS volumes. Copied source certificate/account volumes are retained but not mounted by HTTPS. Copied job history is retained and is not a new result for this group. Keep raw evidence and HDFS volumes when changing the hostname.

The IP is not reserved in the latest verified project inventory. Reserve the current IP if the URL must remain unchanged across stop/start. No VM sizing or GPU changes were made.
