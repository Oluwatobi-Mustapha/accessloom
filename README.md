# Identrail

Identrail is a machine identity security platform.

It discovers machine and workload identities across cloud environments, maps who can assume what, analyzes privilege paths, and surfaces risky identities.

## Current Capabilities

- AWS scan pipeline: collector -> normalizer -> graph -> risk engine
- CLI workflows:
  - `identrail scan`
  - `identrail findings`
- REST API workflows:
  - `POST /v1/scans`
  - `GET /v1/scans`
  - `GET /v1/findings`
- Worker workflow:
  - `worker` runs scheduled scans
- Persistence:
  - memory mode (default)
  - PostgreSQL mode (`IDENTRAIL_DATABASE_URL`)
- Security basics:
  - scan lock
  - bounded list limits
  - scan timeout
  - security response headers
