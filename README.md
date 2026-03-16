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
  - API key auth (`IDENTRAIL_API_KEYS`)
  - write authorization keys for scan trigger (`IDENTRAIL_WRITE_API_KEYS`)
  - scoped API keys (`IDENTRAIL_API_KEY_SCOPES`, example: `reader:read;writer:read,write`)
  - per-IP rate limiting (`IDENTRAIL_RATE_LIMIT_RPM`, `IDENTRAIL_RATE_LIMIT_BURST`)
  - bounded list limits
  - scan timeout
  - security response headers
  - audit log middleware for `/v1/*` + optional file sink (`IDENTRAIL_AUDIT_LOG_FILE`)
- Startup migration support:
  - `IDENTRAIL_RUN_MIGRATIONS`
  - `IDENTRAIL_MIGRATIONS_DIR`
