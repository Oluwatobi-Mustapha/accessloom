# ADR (Architecture Decision Record)

This file tracks major decisions in simple terms.

## ADR-001: Modular Monolith First
- Date: 2026-03-16
- Decision: Start as one deployable service with clean internal modules.
- Why: Faster shipping, easier debugging, less early complexity.
- Tradeoff: Less independent scaling per module at first.

## ADR-002: AWS-First Scope
- Date: 2026-03-16
- Decision: Build full AWS pipeline first. Keep Kubernetes/Azure interfaces ready.
- Why: Smaller scope, faster value, lower risk.
- Tradeoff: Multi-cloud comes later.

## ADR-003: Keep Raw + Normalized Data
- Date: 2026-03-16
- Decision: Store raw provider payloads and normalized entities.
- Why: Better audit trail, better explainability for findings.
- Tradeoff: More storage use.

## ADR-004: Typed Findings
- Date: 2026-03-16
- Decision: Use typed findings (`overprivileged`, `risky_trust`, etc.).
- Why: Easier filtering, stable API contract, clearer remediation.
- Tradeoff: Rule updates need strict schema discipline.

## ADR-005: Idempotent Persistence
- Date: 2026-03-16
- Decision: Use scan-scoped upsert keys for artifacts and findings.
- Why: Safe reruns, no duplicate data growth.
- Tradeoff: More careful key design.

## ADR-006: Single-Flight Scan Lock
- Date: 2026-03-16
- Decision: Reject overlapping scans for same provider.
- Why: Prevent race conditions and duplicate writes.
- Tradeoff: Concurrent trigger requests can return conflict (`409`).

## ADR-007: Memory Store + Postgres Store
- Date: 2026-03-16
- Decision: Keep one store interface with in-memory and Postgres adapters.
- Why: Easy local dev, production-ready path.
- Tradeoff: Two adapters to maintain.

## ADR-008: API Key Auth for v1 Endpoints
- Date: 2026-03-16
- Decision: Protect `/v1/*` with API key middleware when keys are configured.
- Why: Add simple access control with low setup cost.
- Tradeoff: Not full authorization; key rotation must be managed.

## ADR-009: Per-IP Rate Limiter
- Date: 2026-03-16
- Decision: Add per-IP rate limiting middleware for `/v1/*`.
- Why: Reduce abuse and accidental request floods.
- Tradeoff: In-memory limiter is node-local (not distributed).

## ADR-010: Startup Migration Runner
- Date: 2026-03-16
- Decision: Run `*.up.sql` migrations on startup in Postgres mode (configurable).
- Why: Prevent schema drift and startup/runtime mismatch.
- Tradeoff: Requires careful deploy/rollback runbook.

## ADR-011: Split API Keys for Read vs Write
- Date: 2026-03-16
- Decision: Add separate write-key list for scan trigger endpoint.
- Why: Prevent read-only keys from triggering scan runs.
- Tradeoff: Extra key management overhead.

## ADR-012: API Audit Logging Middleware
- Date: 2026-03-16
- Decision: Log each `/v1/*` request with method, path, status, IP, and latency.
- Why: Improve forensic visibility and operational tracing.
- Tradeoff: Must manage log volume and retention.

## ADR-013: Scoped API Keys Override Legacy Lists
- Date: 2026-03-16
- Decision: When scoped keys are configured, use them as the source of truth for authorization.
- Why: Remove ambiguity between read/write key lists and per-key scopes.
- Tradeoff: Migration from legacy key lists needs coordination.

## ADR-014: File Audit Sink for Durable Local Export
- Date: 2026-03-16
- Decision: Support optional JSONL append sink for API audit events.
- Why: Keep a durable audit trail even when centralized logging is not yet connected.
- Tradeoff: Requires file retention and secure file access controls.

## ADR-015: Non-Blocking Webhook Alerts for High-Risk Findings
- Date: 2026-03-16
- Decision: Send scan alerts to a webhook for findings at or above a configured severity threshold.
- Why: Give teams fast signal for critical IAM risk paths without waiting for dashboard polling.
- Tradeoff: Webhook failures are logged but do not fail scan completion.

## ADR-016: Webhook Safety Guardrails
- Date: 2026-03-16
- Decision: Require `https` webhook URLs (allow `http` only for localhost), support optional HMAC signing.
- Why: Reduce accidental insecure transport and allow receiver-side request verification.
- Tradeoff: Slightly stricter setup for dev/test endpoints.

## ADR-017: Scoped Keys Must Pass Explicit Read Authorization
- Date: 2026-03-16
- Decision: Enforce readable scope on `/v1/*` when scoped keys are enabled.
- Why: Prevent keys with unknown/invalid scopes from reading findings and scan history.
- Tradeoff: Existing scoped keys must include `read` or `write`.

## ADR-018: Fail Fast on Invalid Write-Key Configuration
- Date: 2026-03-16
- Decision: Startup fails when legacy write keys are not also present in allowed API keys.
- Why: Prevent silent lockout or inconsistent authorization behavior.
- Tradeoff: Slightly stricter startup config requirements.

## ADR-019: Do Not Persist Raw API Keys in Audit Events
- Date: 2026-03-16
- Decision: Store deterministic API key fingerprints (`api_key_id`) in audit events instead of raw key values.
- Why: Reduce credential exposure risk in logs and exported audit records.
- Tradeoff: Fingerprints are not reversible, so debugging requires key-to-fingerprint mapping.

## ADR-020: Validate Scoped-Key and Alert Bounds at Startup
- Date: 2026-03-16
- Decision: Reject unknown scoped-key scopes and excessive alert max-finding limits during startup validation.
- Why: Prevent silent authorization failures and unbounded alert payload growth.
- Tradeoff: Misconfigured environments fail fast instead of partially starting.

## ADR-021: Persist Scan Lifecycle Events
- Date: 2026-03-16
- Decision: Persist structured scan events (`scan_events`) and expose them through API.
- Why: Improve operational visibility for scan failures and forensic review.
- Tradeoff: Extra write volume per scan.

## ADR-022: Add Scan Diff and Findings Summary Endpoints
- Date: 2026-03-16
- Decision: Provide API-level aggregated views for findings summary and scan-to-scan diff.
- Why: Reduce dashboard/client-side compute and simplify incident triage.
- Tradeoff: Additional server-side compute for diff generation.

## ADR-023: Retry Webhook Alerts on Transient Failures
- Date: 2026-03-16
- Decision: Retry alert webhook delivery on network errors and 5xx responses with bounded backoff.
- Why: Improve delivery reliability without blocking scan completion.
- Tradeoff: Slightly increased outbound request volume during receiver instability.

## ADR-024: Add Explorer-Oriented Identity and Relationship APIs
- Date: 2026-03-16
- Decision: Add `GET /v1/identities` and `GET /v1/relationships` with scan-aware filters.
- Why: Support graph/explorer UI slices without requiring direct database access.
- Tradeoff: Additional query/filter logic in store layer.

## ADR-025: Add Findings Trend API
- Date: 2026-03-16
- Decision: Add `GET /v1/findings/trends` returning scan-aligned severity buckets.
- Why: Enable lightweight trend chart rendering in dashboard clients.
- Tradeoff: Per-request aggregation cost over recent scans.

## ADR-026: Add Optional HTTP Audit Forwarding Sink
- Date: 2026-03-16
- Decision: Allow forwarding audit events to remote collectors with optional HMAC signing.
- Why: Enable centralized audit pipelines before full SIEM integration.
- Tradeoff: Additional outbound dependency and delivery failure handling.

## ADR-027: Establish sqlc Query Contract Scaffolding
- Date: 2026-03-16
- Decision: Add sqlc config/query files now, then migrate runtime store calls to generated code incrementally.
- Why: Introduce typed SQL contract without disruptive refactor in one release.
- Tradeoff: Temporary dual state (manual queries + sqlc scaffolding) until migration is complete.

## ADR-028: Add Filter-First Findings and Trend APIs
- Date: 2026-03-16
- Decision: Support server-side filters for findings, trends, and scan events, plus finding-by-id drill-down.
- Why: Keep dashboard and CLI queries simple and reduce client-side filtering logic.
- Tradeoff: Additional service-layer filtering logic and response-shape tests.

## ADR-029: Retry Audit Forwarding on Transient Failures
- Date: 2026-03-16
- Decision: Retry audit forwarding on network errors and 5xx responses using bounded retry/backoff settings.
- Why: Reduce audit-event loss during short remote collector outages.
- Tradeoff: Slightly higher outbound requests during failures.

## ADR-030: Start Postgres Read Migration to Typed Query Layer
- Date: 2026-03-16
- Decision: Move scan/finding/event read methods to typed query wrappers aligned with sqlc contracts.
- Why: Reduce manual SQL row mapping risk and prepare smooth sqlc generation adoption.
- Tradeoff: Temporary adapter layer before full generated-code cutover.

## ADR-031: Enforce Multi-Stage CI Gates on Every Mainline Change
- Date: 2026-03-16
- Decision: Add GitHub Actions CI with Go quality checks, coverage gate, Postgres integration tests, and web build checks.
- Why: Catch regressions before deploy and keep backend/frontend contracts stable.
- Tradeoff: Slightly longer feedback cycle for large pull requests.
