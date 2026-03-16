# Self Assessment

Updated only at major milestones.

- Scanner pipeline: working end-to-end in fixture mode.
- Persistence: scans + artifacts + findings saved idempotently.
- API: auth, write authorization, rate limiting, timeout, security headers, audit logging.
- API auth model: scoped keys (`read`/`write`) now supported with safe precedence rules.
- API scope enforcement: scoped keys must have readable scope for `/v1/*`.
- Audit durability: optional JSONL file sink for request audit events.
- Alerting: high-severity findings can trigger signed webhook notifications.
- Startup guardrails: invalid write-key setup now fails fast.
- Worker: scheduled process runs scans with shared runtime bootstrap.
- Migrations: startup migration runner added for Postgres mode.
- Test health: `go test ./... -cover` passing, coverage above 80%.
- Next focus: deploy runbook and centralized log shipping hooks.
