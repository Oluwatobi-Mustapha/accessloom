# Self Assessment

Updated only at major milestones.

- Scanner pipeline: working end-to-end in fixture mode.
- Persistence: scans + artifacts + findings saved idempotently.
- API: auth, write authorization, rate limiting, timeout, security headers, audit logging.
- API auth model: scoped keys (`read`/`write`) now supported with safe precedence rules.
- API scope enforcement: scoped keys must have readable scope for `/v1/*`.
- Audit durability: optional JSONL file sink for request audit events.
- Audit secrecy: API keys are fingerprinted in audit events (no raw key values).
- Alerting: high-severity findings can trigger signed webhook notifications.
- Alert reliability: webhook retries/backoff added for transient receiver failures.
- Startup guardrails: invalid write-key setup now fails fast.
- Config hardening: invalid scoped scopes and oversized alert payload settings fail fast.
- Analyst workflows: findings summary, scan diff, and scan event timeline APIs added.
- Explorer workflows: identities, relationships, and findings trend endpoints added.
- Audit forwarding: optional HTTP forward sink with signing guardrails.
- API drill-down: finding-by-id endpoint and server-side findings/trend/event filters added.
- Postgres reads: scan/finding/event reads now use typed query wrappers aligned with sqlc contracts.
- Audit reliability: audit forwarding retries/backoff added with bounded startup validation.
- Delivery gate: production-grade CI pipeline added (quality, coverage, integration, web build).
- API contract: domain payloads standardized to explicit snake_case JSON fields.
- Dashboard: findings filters + scan diff + explorer snapshot shipped with frontend tests.
- Worker: scheduled process runs scans with shared runtime bootstrap.
- Migrations: startup migration runner added for Postgres mode.
- Test health: `go test ./... -cover` passing, coverage above 80%.
- Next focus: deploy runbook and centralized log shipping hooks.
