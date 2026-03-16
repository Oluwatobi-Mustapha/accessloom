# Identrail

Identrail is a machine identity security platform.

It discovers machine and workload identities across cloud environments, maps who can assume what, analyzes privilege paths, and surfaces security findings such as overprivileged, stale, risky, or ownerless identities.

Initial focus is AWS, with architecture hooks for Kubernetes and Azure.

The goal is simple: give security and IAM teams clear visibility and actionable risk insights before identity issues become incidents.

## Current Capabilities

- AWS phase-1 scan pipeline (collector -> normalizer -> graph -> risk engine)
- CLI workflows:
  - `identrail scan`
  - `identrail findings`
- REST API workflows:
  - `POST /v1/scans`
  - `GET /v1/scans`
  - `GET /v1/findings`
- Persistence layer with memory mode (default) and PostgreSQL mode (`IDENTRAIL_DATABASE_URL`)
- Idempotent storage of raw + normalized scan artifacts and typed findings
