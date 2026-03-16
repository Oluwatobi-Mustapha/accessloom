# Testing Strategy

## Principles

- Unit tests for core packages and orchestration paths
- Fixture-based tests for provider collection/normalization/rules
- Sqlmock tests for Postgres store behavior
- Scheduler and worker tests for run safety
- CI must fail fast on formatting, static checks, integration failures, or coverage regressions

## Current Focus

- Config defaults and env parsing
- Scoped API key parsing and write authorization behavior
- Scoped read authorization enforcement behavior (`read` or `write`)
- Audit API-key fingerprint generation behavior (no raw key persistence)
- Webhook alerter URL validation, severity filtering, and non-2xx failure handling
- API routes and scan trigger behavior
- API auth and write-authorization middleware behavior
- API rate-limit and audit-log middleware behavior
- Audit sink file export behavior
- Service non-blocking alert callback behavior
- Startup security config validation and warning coverage (scopes, write-key mapping, alert bounds)
- Scan diff, findings summary, and scan event timeline service behavior
- Router coverage for summary/diff/events endpoints and missing-scan handling
- Router coverage for trends/identities/relationships endpoints and missing-scan handling
- Webhook retry/backoff behavior for transient failures
- HTTP audit forwarding sink behavior and multi-sink fanout behavior
- Memory/Postgres persistence logic
- Migration runner behavior
- Integration lane (build tag `integration`) for Postgres-backed run-scan + diff flow
- Artifact and finding idempotent upserts
- Scheduler lock/runner behavior
- Worker startup and cancellation behavior

## CI Pipeline Gates

GitHub Actions workflow: `.github/workflows/ci.yml`

- `go-quality`
  - `gofmt` enforcement
  - `go vet ./...`
- `go-test`
  - `go test ./... -coverprofile=coverage.out`
  - coverage floor: total >= 80%
- `go-integration`
  - Postgres service container
  - `go test -tags=integration ./internal/integration -count=1 -v`
- `web-build`
  - `npm ci --prefix web`
  - `npm run test:ci --prefix web`
  - `npm run build --prefix web`
