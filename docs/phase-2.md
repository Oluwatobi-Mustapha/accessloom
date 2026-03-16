# Phase 2: Persistence and API

## Goal

Persist scan metadata and findings over time, expose stable API endpoints, and prepare the platform for scheduled idempotent scans.

## Implemented in this milestone series

- PostgreSQL baseline migration set (`migrations/000001_init.up.sql`)
- Storage layer (`internal/db`):
  - `MemoryStore` for local/dev execution
  - `PostgresStore` for production persistence
- API service orchestration:
  - creates scan records
  - runs scanner
  - upserts findings idempotently
  - finalizes scan status and counts
- API endpoints backed by storage:
  - `POST /v1/scans`
  - `GET /v1/scans`
  - `GET /v1/findings`
- full artifact persistence:
  - raw assets, identities, policies, relationships, permissions, findings
- Scheduler foundation and lock-based idempotency:
  - keyed in-memory scan lock
  - periodic runner abstraction
  - conflict protection for concurrent scan triggers
- Config wiring:
  - `IDENTRAIL_DATABASE_URL`
  - `IDENTRAIL_AWS_FIXTURES`

## Idempotency approach

- Findings are persisted with composite key `(scan_id, finding_id)` and upsert semantics.
- Raw and normalized artifacts are persisted with scan-scoped upsert keys.
- Scan triggers are protected by single-flight provider lock (`scan:<provider>`).
- Re-running persistence for the same scan does not duplicate findings.

## Next milestones

1. Scheduled worker process and startup wiring for periodic scans
2. Persist normalized entities/relationships during scans
3. API filtering and pagination hardening
