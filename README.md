# Identrail

Identrail is a machine identity security platform.

It discovers machine and workload identities across cloud environments, maps who can assume what, analyzes privilege paths, and surfaces risky identities.

Operational runbook: `docs/deploy-runbook.md`.
Portable deployment guide: `docs/deployment-anywhere.md`.
Repository exposure scanner guide: `docs/repo-exposure.md`.
Web shell scaffold: `web/` (React + TypeScript + Vite).

## Current Capabilities

- AWS scan pipeline: collector -> normalizer -> graph -> risk engine
  - source modes: `fixture` and live `sdk`
- Kubernetes scan pipeline:
  - fixture mode (`IDENTRAIL_K8S_SOURCE=fixture`)
  - live kubectl mode (`IDENTRAIL_K8S_SOURCE=kubectl`)
- CLI workflows:
  - `identrail scan`
  - `identrail findings`
  - `identrail repo-scan --repo <owner/repo|url|local-path>`
- REST API workflows:
  - `POST /v1/scans`
  - `POST /v1/repo-scans`
  - `GET /v1/repo-scans`
  - `GET /v1/repo-scans/:repo_scan_id`
  - `GET /v1/repo-findings`
  - `GET /v1/scans`
  - `GET /v1/scans/:scan_id/diff`
  - `GET /v1/scans/:scan_id/events`
  - `GET /v1/findings`
  - `GET /v1/findings/summary`
  - `GET /v1/findings/trends`
  - `GET /v1/identities`
  - `GET /v1/relationships`
- Worker workflow:
  - `worker` runs scheduled scans
- Dashboard workflow (`web/`):
  - findings table with severity/type filters
  - scan selector with diff snapshot
  - identity/relationship/event explorer snapshot
- Persistence:
  - memory mode (default)
  - PostgreSQL mode (`IDENTRAIL_DATABASE_URL`)
- Security basics:
  - scan lock
  - API key auth (`IDENTRAIL_API_KEYS`)
  - write authorization keys for scan trigger (`IDENTRAIL_WRITE_API_KEYS`)
  - scoped API keys (`IDENTRAIL_API_KEY_SCOPES`, example: `reader:read;writer:read,write`)
  - scope enforcement on `/v1/*` (`read` required, `write` implies `read`)
  - high-severity scan alert webhook (`IDENTRAIL_ALERT_WEBHOOK_URL`)
  - alert threshold + bounds (`IDENTRAIL_ALERT_MIN_SEVERITY`, `IDENTRAIL_ALERT_MAX_FINDINGS`)
  - optional webhook request signing (`IDENTRAIL_ALERT_HMAC_SECRET`)
  - alert retry controls (`IDENTRAIL_ALERT_MAX_RETRIES`, `IDENTRAIL_ALERT_RETRY_BACKOFF`)
  - startup security config validation (prevents invalid read/write key setups)
  - scoped-key validation (rejects unknown scopes at startup)
  - per-IP rate limiting (`IDENTRAIL_RATE_LIMIT_RPM`, `IDENTRAIL_RATE_LIMIT_BURST`)
  - bounded list limits
  - scan timeout
  - security response headers
  - audit log middleware for `/v1/*` + optional file sink (`IDENTRAIL_AUDIT_LOG_FILE`)
  - optional audit forwarding sink (`IDENTRAIL_AUDIT_FORWARD_URL`)
  - audit events use API key fingerprints (`api_key_id`), not raw keys
- Startup migration support:
  - `IDENTRAIL_RUN_MIGRATIONS`
  - `IDENTRAIL_MIGRATIONS_DIR`
- Kubernetes live collection config:
  - `IDENTRAIL_K8S_SOURCE` (`fixture` or `kubectl`)
  - `IDENTRAIL_KUBECTL_PATH`
  - `IDENTRAIL_KUBE_CONTEXT`
- AWS live collection config:
  - `IDENTRAIL_AWS_SOURCE` (`fixture` or `sdk`)
  - `IDENTRAIL_AWS_REGION`
  - `IDENTRAIL_AWS_PROFILE` (optional)
- Repo exposure scan config:
  - `IDENTRAIL_REPO_SCAN_ENABLED`
  - `IDENTRAIL_REPO_SCAN_HISTORY_LIMIT`
  - `IDENTRAIL_REPO_SCAN_MAX_FINDINGS`
  - `IDENTRAIL_REPO_SCAN_HISTORY_LIMIT_MAX`
  - `IDENTRAIL_REPO_SCAN_MAX_FINDINGS_MAX`
  - `IDENTRAIL_REPO_SCAN_ALLOWLIST` (comma list, supports `prefix*` wildcard)
- CI gates:
  - GitHub Actions pipeline for Go quality checks, coverage, Postgres integration tests, and web build validation

## Deployment Profiles

- Docker Compose (single host):
  - `deploy/docker/docker-compose.yml`
- Kubernetes:
  - `deploy/kubernetes/`
- Linux VM + systemd:
  - `deploy/systemd/`
