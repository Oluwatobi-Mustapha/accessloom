# Phase 2: Persistence and API

## Goal

Persist scan metadata and findings over time, expose stable API endpoints, and run scans safely on a schedule.

## Implemented in this milestone series

- PostgreSQL baseline migration set (`migrations/000001_init.up.sql`)
- Scan event migration set (`migrations/000002_scan_events.up.sql`)
- Storage layer (`internal/db`):
  - `MemoryStore` for local/dev execution
  - `PostgresStore` for production persistence
- Startup migration runner:
  - applies `*.up.sql` files in order
  - enabled by default in Postgres mode
- API service orchestration:
  - creates scan records
  - runs scanner
  - upserts full artifacts and findings idempotently
  - finalizes scan status and counts
- API endpoints backed by storage:
  - `POST /v1/scans`
  - `GET /v1/scans`
  - `GET /v1/scans/:scan_id/diff`
  - `GET /v1/scans/:scan_id/events`
  - `GET /v1/findings`
  - `GET /v1/findings/:finding_id`
  - `GET /v1/findings/summary`
  - `GET /v1/findings/trends`
  - `GET /v1/identities`
  - `GET /v1/relationships`
- API filters and drill-down:
  - findings filters: `scan_id`, `severity`, `type`
  - trends filters: `severity`, `type`
  - scan event filters: `level`
  - scan diff baseline override: `previous_scan_id`
  - finding drill-down by id, with optional `scan_id` scope
- Full artifact persistence:
  - raw assets, identities, policies, relationships, permissions, findings
- SQL query scaffolding:
  - `sqlc/sqlc.yaml`
  - query contracts under `sqlc/queries/`
  - typed query wrapper consumed by Postgres read paths (`GetScan`, scan list, findings list, scan events)
- Scheduler and worker:
  - keyed in-memory scan lock
  - periodic runner abstraction
  - worker binary (`cmd/worker`) for scheduled scans
- API hardening:
  - API key auth middleware
  - write authorization keys for scan trigger
  - scoped API key model (`read`/`write`) with precedence over legacy key lists
  - explicit read-scope enforcement on `/v1/*` endpoints
  - startup validation for scoped-key scope values
  - per-IP rate limiting
  - request timeout and security headers
  - audit request logging
  - optional audit log file export sink
  - optional audit forwarding sink (HTTP)
  - API key fingerprinting in audit events (no raw key logging)
- Alerting:
  - high-severity finding webhook notifications
  - severity threshold and max finding cap
  - optional HMAC request signing
  - retry/backoff policy for transient webhook failures
  - non-blocking delivery (scan success does not depend on webhook success)
- Startup guardrails:
  - reject invalid read/write key combinations early
  - reject invalid scoped-key scope names early
  - reject oversized alert payload limits
  - emit security warnings for risky but allowed config states

## Config wiring

- `IDENTRAIL_DATABASE_URL`
- `IDENTRAIL_AWS_FIXTURES`
- `IDENTRAIL_SCAN_INTERVAL`
- `IDENTRAIL_WORKER_RUN_NOW`
- `IDENTRAIL_API_KEYS`
- `IDENTRAIL_WRITE_API_KEYS`
- `IDENTRAIL_API_KEY_SCOPES`
- `IDENTRAIL_RATE_LIMIT_RPM`
- `IDENTRAIL_RATE_LIMIT_BURST`
- `IDENTRAIL_RUN_MIGRATIONS`
- `IDENTRAIL_MIGRATIONS_DIR`
- `IDENTRAIL_AUDIT_LOG_FILE`
- `IDENTRAIL_AUDIT_FORWARD_URL`
- `IDENTRAIL_AUDIT_FORWARD_TIMEOUT`
- `IDENTRAIL_AUDIT_FORWARD_MAX_RETRIES`
- `IDENTRAIL_AUDIT_FORWARD_RETRY_BACKOFF`
- `IDENTRAIL_AUDIT_FORWARD_HMAC_SECRET`
- `IDENTRAIL_ALERT_WEBHOOK_URL`
- `IDENTRAIL_ALERT_MIN_SEVERITY`
- `IDENTRAIL_ALERT_TIMEOUT`
- `IDENTRAIL_ALERT_HMAC_SECRET`
- `IDENTRAIL_ALERT_MAX_FINDINGS`
- `IDENTRAIL_ALERT_MAX_RETRIES`
- `IDENTRAIL_ALERT_RETRY_BACKOFF`

## Idempotency approach

- Findings use upsert key `(scan_id, finding_id)`.
- Raw/normalized artifacts use scan-scoped upsert keys.
- Scan triggers are protected by provider lock (`scan:<provider>`).

## Next milestones

1. migrate Postgres store queries to generated sqlc package
2. role/scope policy hardening guide for key rotation
3. dashboard UI consumption for trends/explorer endpoints
