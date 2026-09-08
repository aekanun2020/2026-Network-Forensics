# Stage canonical NF-01 evidence on student-1

- Started UTC: 2026-09-08T14:43:41.220849+00:00
- Actor: Codex / thaimcpagent@gmail.com via OS Login and sudo.
- Project / VM / zone: bigdatainpractice1 / student-1 / asia-southeast1-a.
- Authorization: user asked to continue the NF-01 lab installation.
- Before: no NF-01 raw data in VM/HDFS. Local destination-repository ZIP and raw SHA-256 checks passed for all six files, total 200122121 bytes.
- Planned actions: transfer exactly six raw files as a compressed archive; unpack under /opt/nf01/imports; copy into HDFS /mcp/student/agentic-siem/incident-lab/input using namenode administrator; set raw files and input directories read-only for ordinary spark identity; create four named output directories. Verify size and hashes using real MCP tools.
- Scope: no other datasets, reference answers, model calls, or firewall changes. Remove the upstream case-specific integration-test source accidentally included in the administrator-only initial staging bundle; it was not copied into the MCP image or imported to HDFS. Keep that source only in the operator repository.
- Integrity: expected files and hashes are in ../platform/nf01/evidence-inventory.json; verification results recorded separately.
- Cost: transfer and disk usage on existing VM; no new GCP resources. HDFS replication is 2.
- Status: completed; see recorded results below.
- Recovery: raw source ZIPs remain unchanged in the destination repository; no automatic destructive cleanup.

## Import result

Completed: exactly six HDFS input files, total 200122121 bytes; replication=2, owner root:supergroup, file permissions 444, input directory 555. Four named output directories created; all currently use the same spark identity and are not separate security domains. No raw file hash mismatch during local/VM pre-import checks. Case-specific test source removed from VM staging. Real MCP integrity verification follows.

## Final staging cleanup planned

Remove only the `.gitkeep` placeholder and macOS `._*` metadata sidecars introduced by our archive transfer in /opt/nf01/imports; retain exactly the six verified raw files. Copy the final operator README into /opt/nf01 and retain test artifacts. No raw byte changes.

Final staging cleanup completed: imports contains exactly the six raw files. The operator README was updated.

Record finalized UTC: 2026-09-08T14:59:31.287035+00:00
