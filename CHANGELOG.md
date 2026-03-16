# Changelog

## Unreleased
- Added scoped read authorization enforcement on `/v1/*` when using scoped API keys.
- Added startup security validation for legacy write key configuration.
- Added startup security warning emission for risky but allowed config states.
- Added high-severity findings webhook alerts with configurable threshold and cap.
- Added optional HMAC signing for alert webhook requests.
- Added webhook safety guardrails (`https` required for remote endpoints).
- Added scoped API key authorization config (`IDENTRAIL_API_KEY_SCOPES`) with legacy fallback behavior.
- Added optional audit file export sink (`IDENTRAIL_AUDIT_LOG_FILE`) for durable API request audit events.
- Added write authorization keys for scan trigger endpoint (`IDENTRAIL_WRITE_API_KEYS`).
- Added API audit logging middleware for `/v1/*` requests.
- Added API key authentication middleware for `/v1/*` endpoints.
- Added per-IP rate limiter middleware.
- Added startup migration runner for Postgres mode.
- Added worker process for scheduled scans (`cmd/worker`).
- Added shared runtime service bootstrap (`internal/runtime`).
- Added worker scheduling config (`IDENTRAIL_SCAN_INTERVAL`, `IDENTRAIL_WORKER_RUN_NOW`).
- Kept self assessment short and milestone-based (`docs/self_assessment.md`).

## 2026-03-16
- Phase 1 foundation completed.
- AWS collector, normalizer, graph, risk engine, and CLI workflow completed.
- Project renamed to `identrail`.
- Phase 2 started: migrations, store layer, persistence-backed API.
- Scheduler lock and single-flight scan trigger support added.
- Full artifact persistence (raw + normalized + findings) added.
- ADR, threat model, and baseline security hardening added.
