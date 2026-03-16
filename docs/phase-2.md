# Phase 2: Persistence and API

## Goal

Persist scan metadata and findings over time, expose stable API endpoints, and run scans safely on a schedule.

## Implemented in this milestone series

- PostgreSQL baseline migration set (`migrations/000001_init.up.sql`)
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
  - `GET /v1/findings`
- Full artifact persistence:
  - raw assets, identities, policies, relationships, permissions, findings
- Scheduler and worker:
  - keyed in-memory scan lock
  - periodic runner abstraction
  - worker binary (`cmd/worker`) for scheduled scans
- API hardening:
  - API key auth middleware
  - write authorization keys for scan trigger
  - per-IP rate limiting
  - request timeout and security headers
  - audit request logging

## Config wiring

- `IDENTRAIL_DATABASE_URL`
- `IDENTRAIL_AWS_FIXTURES`
- `IDENTRAIL_SCAN_INTERVAL`
- `IDENTRAIL_WORKER_RUN_NOW`
- `IDENTRAIL_API_KEYS`
- `IDENTRAIL_WRITE_API_KEYS`
- `IDENTRAIL_RATE_LIMIT_RPM`
- `IDENTRAIL_RATE_LIMIT_BURST`
- `IDENTRAIL_RUN_MIGRATIONS`
- `IDENTRAIL_MIGRATIONS_DIR`

## Idempotency approach

- Findings use upsert key `(scan_id, finding_id)`.
- Raw/normalized artifacts use scan-scoped upsert keys.
- Scan triggers are protected by provider lock (`scan:<provider>`).

## Next milestones

1. role/scope-based authorization model (beyond API keys)
2. audit log export stream and alert hooks
3. production deploy docs for migration/rollback runbook
