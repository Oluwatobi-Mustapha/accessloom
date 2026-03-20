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

## ADR-032: Standardize API Payloads to snake_case
- Date: 2026-03-16
- Decision: Add explicit JSON tags to core domain models used in API responses.
- Why: Keep payload shape stable for frontend and external clients, avoid implicit struct-name casing leaks.
- Tradeoff: Existing consumers that depended on title-case fields must migrate.

## ADR-033: Support Explicit Baseline Scan Selection for Diff
- Date: 2026-03-16
- Decision: Allow `previous_scan_id` on scan diff endpoint to compare against a chosen earlier scan.
- Why: Operators need deterministic historical comparisons, not only auto-previous scan behavior.
- Tradeoff: Additional validation logic for provider match and scan ordering.

## ADR-034: Add Kubernetes Fixture Pipeline Before Live Cluster Collector
- Date: 2026-03-16
- Decision: Implement Kubernetes support first with fixture collector + normalized pipeline, then add live API collector.
- Why: Keep scope narrow, stabilize domain mapping/rules, and ship deterministic tests before cluster auth/network complexity.
- Tradeoff: Early Kubernetes mode is simulation-first and does not yet pull from live clusters.

## ADR-035: Ship Multi-Target Deployment Profiles
- Date: 2026-03-16
- Decision: Add first-class deploy profiles for Docker Compose, Kubernetes manifests, and systemd units.
- Why: Make adoption practical across startups and enterprises without forcing one platform choice.
- Tradeoff: More deployment artifacts to maintain in sync with runtime config changes.

## ADR-036: Add Kubernetes Live Collection Mode via Kubectl
- Date: 2026-03-17
- Decision: Add `IDENTRAIL_K8S_SOURCE=kubectl` mode for read-only live cluster collection while keeping fixture mode as default.
- Why: Enable real environment scans now without blocking on full client-go integration complexity.
- Tradeoff: Requires `kubectl` binary/context availability and shell execution controls.

## ADR-037: Add AWS Live Collection Mode via SDK
- Date: 2026-03-17
- Decision: Add `IDENTRAIL_AWS_SOURCE=sdk` mode to collect IAM roles and policies using AWS SDK while retaining fixture mode.
- Why: Enable direct onboarding for real AWS environments without replacing deterministic fixture workflows.
- Tradeoff: Requires valid AWS credentials and region configuration; IAM API rate limits must be handled operationally.

## ADR-038: Resolve Kubernetes Bindings from Real RBAC Role Rules
- Date: 2026-03-17
- Decision: Collect `Role` and `ClusterRole` objects and expand role bindings from their concrete RBAC `rules` first.
- Why: Avoid false confidence and drift from role-name-only heuristics when custom roles are used.
- Tradeoff: More collection calls and normalization logic; still keep heuristic fallback when role objects are unavailable.

## ADR-039: Add Repository Exposure Scanner as Separate CLI Module
- Date: 2026-03-17
- Decision: Add `repo-scan` as a dedicated, read-only CLI workflow separate from cloud identity scan pipelines.
- Why: Detect public-repo secret leaks and misconfigurations without coupling repository scanning to AWS/Kubernetes domain models.
- Tradeoff: Results are currently CLI-driven and not yet persisted through API scan lifecycle endpoints.

## ADR-040: Expose Repo Scan Through Write-Protected API Endpoint
- Date: 2026-03-17
- Decision: Add `POST /v1/repo-scans` with write authorization and configurable safety bounds/allowlist.
- Why: Enable dashboard/backend integrations to trigger repository exposure scans without shell access.
- Tradeoff: Endpoint is synchronous and currently returns findings directly (no persistence lifecycle yet).

## ADR-041: Persist Repo Scan Lifecycle in Dedicated Tables
- Date: 2026-03-17
- Decision: Add `repo_scans` and `repo_findings` tables plus read APIs (`GET /v1/repo-scans`, `GET /v1/repo-findings`) rather than reusing cloud scan tables.
- Why: Preserve backward compatibility for existing `/v1/scans` consumers while enabling durable repo exposure history.
- Tradeoff: Additional persistence paths to maintain in memory/postgres adapters.

## ADR-042: Add Optional Scheduled Repo Scans in Worker with Per-Target Locking
- Date: 2026-03-17
- Decision: Add opt-in worker scheduler for repository scans (`IDENTRAIL_WORKER_REPO_SCAN_*`) and enforce `repo-scan:<target>` lock in service execution.
- Why: Keep continuous repo exposure monitoring in-platform while preserving backward compatibility and avoiding same-target overlap between API and worker.
- Tradeoff: Additional worker configuration and lock semantics to maintain.

## ADR-043: Add Postgres Advisory Lock Backend for Multi-Instance Safety
- Date: 2026-03-17
- Decision: Add configurable lock backend (`IDENTRAIL_LOCK_BACKEND=auto|postgres|inmemory`) with Postgres advisory locks in database deployments.
- Why: In-memory locks are node-local; distributed lock is required to prevent overlapping scans across multiple API/worker instances.
- Tradeoff: Lock acquisition depends on database connectivity and lock namespace configuration.

## ADR-044: Add Cursor Pagination and Ownership Signals API
- Date: 2026-03-17
- Decision: Add additive cursor pagination (`cursor`, `next_cursor`) to list endpoints and `GET /v1/ownership/signals` inferred from identity metadata.
- Why: Keep API stable for large datasets and improve remediation accountability without introducing heavy new persistence paths.
- Tradeoff: Current cursor strategy is offset-based and can be less efficient at very high offsets.

## ADR-045: Freeze V1 Runtime Scope to AWS + Kubernetes
- Date: 2026-03-19
- Decision: Enforce provider guardrails so V1 runtime only accepts `aws` or `kubernetes`; keep repository exposure scanning optional and isolated.
- Why: Protect V1 delivery quality by locking scope to core machine identity workflows and preventing unstable multi-provider drift.
- Tradeoff: Azure runtime collection remains deferred until post-V1 milestones.

## ADR-046: Add OIDC/OAuth2-Compatible Auth Alongside API Keys
- Date: 2026-03-19
- Decision: Add OIDC issuer/audience verification support and allow bearer-token auth with scope-based write authorization.
- Why: Support enterprise SSO/IdP patterns (including Keycloak-compatible setups) without breaking existing API-key automation.
- Tradeoff: Mixed API key + OIDC deployments increase auth-path complexity and require explicit operational testing.

## ADR-047: Add Standards-Aligned Finding Enrichment and Export
- Date: 2026-03-19
- Decision: Enrich findings with control references/framework metadata and add OCSF/ASFF export payload support.
- Why: Keep internal typed finding contracts while enabling downstream integrations and compliance mapping with minimal friction.
- Tradeoff: Requires ongoing maintenance of control mapping catalog as rules evolve.

## ADR-048: Freeze Graph Semantics with Explicit Relationship Contract
- Date: 2026-03-19
- Decision: Explicitly define supported relationship semantics (`can_assume`, `attached_policy`, `attached_to`, `bound_to`, `can_access`, `can_impersonate`) and validate relationship types against this contract.
- Why: Prevent silent graph-schema drift that would break findings logic, API consumers, and path analysis semantics.
- Tradeoff: New relationship types require explicit contract updates before rollout.

## ADR-049: Enforce Deterministic Risk Evidence Ordering
- Date: 2026-03-19
- Decision: Sort access risks before building overprivileged/escalation findings so evidence and path selection remain deterministic.
- Why: Stable finding evidence is required for reliable scan diffs, regression tests, and operator trust.
- Tradeoff: Small additional sorting overhead during rule evaluation.

## ADR-050: Add Retry Jitter to AWS Live Collector
- Date: 2026-03-19
- Decision: Add bounded jitter to AWS IAM retry backoff with deterministic override hooks for tests.
- Why: Reduce synchronized retry bursts under throttling and improve production scan reliability.
- Tradeoff: Retry timing becomes non-uniform, so deterministic tests need explicit jitter overrides.

## ADR-051: Add Collector Diagnostics Contract for Partial Failures
- Date: 2026-03-19
- Decision: Add optional `CollectWithDiagnostics` provider interface returning non-fatal source errors with collected assets.
- Why: Preserve scan continuity when partial provider data is malformed/unavailable while still exposing operator-visible reliability signal.
- Tradeoff: Service layer must handle both full-fail and partial-fail collector paths.

## ADR-052: Enforce Normalized Schema Contract Validation Before Persistence
- Date: 2026-03-19
- Decision: Validate normalized bundles for required fields, uniqueness, and policy payload structure before graph/risk persistence.
- Why: Prevent malformed provider-normalized payloads from entering storage and creating hard-to-debug downstream findings drift.
- Tradeoff: Stricter validation can fail scans that previously completed with weakly structured data.

## ADR-053: Enforce Graph Contract Validation and Semantic Uniqueness
- Date: 2026-03-19
- Decision: Validate relationship endpoint integrity and enforce both ID and semantic tuple uniqueness (`type/from/to`).
- Why: Prevent graph corruption and duplicate-edge semantics that can inflate paths and create unstable finding outcomes.
- Tradeoff: Relationship builders must now satisfy stricter endpoint/type contract checks.

## ADR-054: Add Bounded Scheduler Retry + Dead-Letter Hook
- Date: 2026-03-19
- Decision: Extend scheduler runner with bounded retries, exponential backoff, and dead-letter callback on terminal failure.
- Why: Improve resilience to transient scan failures while creating a clear operational hook for unrecoverable errors.
- Tradeoff: Retries add runtime delay before final failure state is surfaced.

## ADR-055: Persist Partial Scan Lifecycle State
- Date: 2026-03-19
- Decision: Introduce explicit `partial` lifecycle state event when scans complete with non-fatal source diagnostics.
- Why: Operators need deterministic distinction between clean-success and degraded-success runs for incident triage.
- Tradeoff: Clients consuming scan events must account for one additional lifecycle state.
