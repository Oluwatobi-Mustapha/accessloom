# Phase 2: Persistence and API

## Goal

Persist scan metadata and findings over time, expose stable API endpoints, and prepare the platform for scheduled idempotent scans.

## Implemented in this milestone

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
- Config wiring:
  - `IDENTRAIL_DATABASE_URL`
  - `IDENTRAIL_AWS_FIXTURES`

## Idempotency approach

- Findings are persisted with composite key `(scan_id, finding_id)` and upsert semantics.
- Re-running persistence for the same scan does not duplicate findings.

## Next milestones

1. Scheduler with scan locking and rerun protection
2. Persist normalized entities/relationships during scans
3. API filtering and pagination hardening
