# NF-01 container platform — internal installation verified; learner access pending

Runtime source is pinned in [UPSTREAM.json](UPSTREAM.json). Deployment uses the [original Compose](docker-compose.yml) and [lab override](compose.lab.yml). [HDFS configuration](hadoop/hdfs-site.xml) enables permissions; after import the raw input tree will be owned by root and read-only to the normal spark identity. Simple-auth HDFS is not a security boundary against arbitrary submitted code that impersonates other users. Public learner access remains disabled pending authentication and isolation work.

## Operator files

- [Source inventory](UPSTREAM.json)
- [Lab resource and log limits](compose.lab.yml)
- [MCP server](mcp-server/server.py)
- [Evidence tools](mcp-server/evidence_tools.py)
- [Canonical question and six input hashes](../../cases/01-investigate-10.70.0.66/QUESTION.md)
- [Cloud activity records](../../cloud-activities/README.md)

Run `sudo docker compose -f docker-compose.yml -f compose.lab.yml up -d --build` from the installation directory. All published ports bind to 127.0.0.1. No GCP firewall changes are performed by these files. Skills MCP runs with an empty catalog until an in-scope catalog is selected; no reference answers, other datasets or attack-specific skills are staged.

Initial installation is an administrator-only environment. Per-user authenticated workspaces are not yet implemented. Spark admission is bounded to 2 active jobs and 8 total admitted jobs; queued work is marked INTERRUPTED after server restart and is never silently replayed. Do not distribute this endpoint as a ready four-user lab.

- [Six-file evidence inventory](evidence-inventory.json)
- [Administrator import script](import_evidence.py)
- [Live integration checks](verify_live.py)

## Verified on student-1

8 containers healthy. Six raw files verified through real MCP. Four concurrent SDK sessions and four Spark count jobs passed, with at most 2 jobs RUNNING. Queue-full, idempotent replay, and cancellation tests passed. See [recorded results](../../cloud-activities/evidence/2026-09-08-deployment-summary.json). Disk observed after the main test: 7.6 GiB used / 89 GiB available. This is not a Claude Desktop test.

- [Queue control test](verify_queue.py)

## Learner connection decision

On 2026-09-08 the user selected an HTTPS URL for Claude Desktop. SSH is not the selected learner connection method. The user currently has no domain/subdomain or OAuth/login service. The public hostname, certificate setup, authentication implementation, and authenticated learner identities remain unresolved; no public access has been enabled.

Before distribution, complete authenticated access and workspace isolation, test the real Claude Desktop connection with the six canonical inputs, and record the outcome. The user will manage GCP firewall changes; supply the exact rules after the ingress design is established. Do not expose the current unauthenticated MCP, Spark, HDFS, or skills ports as a substitute. This decision record does not provision additional GCP resources or register a domain.
