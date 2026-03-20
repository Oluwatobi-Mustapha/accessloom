# Threat Model

Simple threat list for current system.

## 1) Overlapping Scan Runs
- Threat: Two scans write at same time and cause inconsistent results.
- Fix: Single-flight lock per provider (`scan:<provider>`).
- Status: Implemented.

## 2) Duplicate Data on Rerun
- Threat: Re-running same flow keeps inserting duplicates.
- Fix: Upsert keys for raw assets, identities, policies, relationships, permissions, findings.
- Status: Implemented.

## 3) Broad Trust + Broad Permission Escalation
- Threat: External principal can assume role with admin-like permissions.
- Fix: Risk engine rule for escalation path and risky trust findings.
- Status: Implemented.

## 4) API Trigger Abuse
- Threat: Repeated scan trigger calls can overload service.
- Fix: Single-flight lock and API conflict response for in-flight run.
- Status: Implemented.

## 5) Unbounded List Queries
- Threat: Very high `limit` may cause performance issues.
- Fix: Clamp API `limit` with max cap.
- Status: Implemented.

## 6) Missing Security Response Headers
- Threat: Weak default API hardening.
- Fix: Add API security headers middleware.
- Status: Implemented.

## 7) Unauthenticated API Access
- Threat: Anyone can trigger scans or read findings.
- Fix: API key authentication for `/v1/*` endpoints.
- Status: Implemented.

## 8) Unauthorized Scan Trigger
- Threat: Read-only API key can still trigger write actions.
- Fix: Dedicated write authorization key list for `POST /v1/scans`.
- Status: Implemented.

## 9) Excessive Request Flood
- Threat: Repeated requests can degrade API availability.
- Fix: Per-IP rate limiter.
- Status: Implemented.

## 10) Missing API Audit Trail
- Threat: Hard to investigate who called sensitive endpoints.
- Fix: API audit log middleware on `/v1/*`.
- Status: Implemented.

## 11) Misconfigured Database Connection Pool
- Threat: Too many DB connections or long-lived bad connections.
- Fix: Set safe Postgres pool defaults.
- Status: Implemented.

## 12) Schema Drift on Startup
- Threat: Service starts on old schema and fails at runtime.
- Fix: Startup migration runner for Postgres mode.
- Status: Implemented.

## 13) Scope Confusion in API Key Authorization
- Threat: Mixed legacy key lists and scoped keys can produce wrong access behavior.
- Fix: Scoped key map takes precedence when configured (`IDENTRAIL_API_KEY_SCOPES`).
- Status: Implemented.

## 14) Missing Durable Audit Export
- Threat: Request logs in process output can be lost during log rotation or collection issues.
- Fix: Optional JSONL audit file sink (`IDENTRAIL_AUDIT_LOG_FILE`) with append-only writes.
- Status: Implemented.

## 15) Delayed Response to Critical Findings
- Threat: Teams may not notice severe findings quickly if they only pull from API/UI later.
- Fix: High-severity webhook alert hook with threshold filter.
- Status: Implemented.

## 16) Webhook Tampering or Spoofed Alerts
- Threat: A receiver may accept forged alert calls.
- Fix: Optional HMAC signature header (`IDENTRAIL_ALERT_HMAC_SECRET`) for receiver verification.
- Status: Implemented.

## 17) Insecure Alert Transport
- Threat: Webhook URL using plain HTTP can leak sensitive finding context.
- Fix: Require `https` for remote endpoints (allow `http` only for localhost development).
- Status: Implemented.

## 18) Invalid Scoped Key Still Reads API Data
- Threat: A key with an unknown scope might authenticate but still read sensitive endpoints.
- Fix: Enforce readable scope on `/v1/*`; `write` implies `read`.
- Status: Implemented.

## 19) Misconfigured Write-Key List
- Threat: Write key exists but is not allowed in base API key list, causing broken or confusing auth behavior.
- Fix: Startup validation rejects invalid legacy write-key configuration.
- Status: Implemented.

## 20) Raw API Key Leakage Through Audit Records
- Threat: Persisting raw API keys in audit logs can expose secrets to operators or downstream systems.
- Fix: Replace raw API key values with deterministic fingerprint IDs.
- Status: Implemented.

## 21) Invalid Scoped-Key Configuration
- Threat: Unknown scope names can silently block access and create unsafe operational workarounds.
- Fix: Startup validation rejects scoped keys with invalid/empty scopes.
- Status: Implemented.

## 22) Oversized Alert Payload Settings
- Threat: Very large max finding settings can produce oversized webhook payloads.
- Fix: Startup validation enforces a max cap for alert payload finding count.
- Status: Implemented.

## 23) Missing Scan Execution Forensics
- Threat: Teams cannot quickly explain where a scan failed in pipeline lifecycle.
- Fix: Persist and expose scan lifecycle events.
- Status: Implemented.

## 24) Hidden Drift Between Consecutive Scans
- Threat: Operators must manually compare findings to understand change impact.
- Fix: Add scan diff endpoint (`/v1/scans/:scan_id/diff`).
- Status: Implemented.

## 25) Alert Loss During Receiver Outage
- Threat: A single webhook failure can drop a critical alert.
- Fix: Bounded retry/backoff for transient failures.
- Status: Implemented.

## 26) Insecure Audit Forwarding Transport
- Threat: Forwarding audit events over insecure transport can leak sensitive request metadata.
- Fix: Require `https` for remote audit forwarding URLs (allow `http` only for localhost).
- Status: Implemented.

## 27) Weak Scan Event Semantics
- Threat: Unbounded/invalid event level values reduce operational signal quality.
- Fix: Enforce typed scan event levels (`debug`, `info`, `warn`, `error`).
- Status: Implemented.

## 28) Audit Forward Event Loss During Collector Outage
- Threat: Temporary collector outages can drop API audit events.
- Fix: Bounded retries and backoff for audit forwarding on transient failures.
- Status: Implemented.

## 29) Heavy Client-Side Filtering Can Cause Query Drift
- Threat: Different clients may compute filters differently and show inconsistent risk data.
- Fix: Add server-side filters (`scan_id`, `severity`, `type`, `level`) and finding detail endpoint.
- Status: Implemented.

## 30) Regressions Reach Production Due to Missing Release Gates
- Threat: Undetected code quality, database, or frontend build issues can ship to production.
- Fix: Enforce CI gates for formatting, static checks, coverage floor, Postgres integration tests, and web build.
- Status: Implemented.

## 31) API Contract Casing Drift Breaks Clients
- Threat: Implicit JSON field names (`ID`, `ScanID`) can drift and break frontend or external consumers.
- Fix: Explicit `snake_case` JSON tags on domain response models + frontend contract tests.
- Status: Implemented.

## 32) Wrong Baseline Selection Skews Drift Analysis
- Threat: Comparing a scan against an invalid baseline (same scan, newer scan, or different provider) gives misleading risk movement.
- Fix: Validate `previous_scan_id` strictly and reject invalid baselines with `400`.
- Status: Implemented.

## 33) Namespace/Subject Drift in Kubernetes Role Bindings
- Threat: A role binding subject with missing namespace/name can map privileges to the wrong identity or produce noisy graph edges.
- Fix: Normalize only valid service account subjects and skip malformed subjects/bindings.
- Status: Implemented.

## 34) Environment Drift Across Deployment Targets
- Threat: Different host/container/cluster setups can drift in env vars and weaken security controls.
- Fix: Ship versioned deployment profiles and env templates (Docker, Kubernetes, systemd) with explicit required variables.
- Status: Implemented.

## 35) Wrong Kubernetes Context Collection
- Threat: Running with the wrong kube context can collect from the wrong cluster and generate misleading findings.
- Fix: Explicit `IDENTRAIL_KUBE_CONTEXT` support and startup validation for allowed k8s source modes.
- Status: Implemented.

## 36) Wrong AWS Account/Region Collection
- Threat: Running scans against the wrong AWS account or region can produce misleading findings and false confidence.
- Fix: Explicit AWS source mode/region config (`IDENTRAIL_AWS_SOURCE`, `IDENTRAIL_AWS_REGION`, optional `IDENTRAIL_AWS_PROFILE`) with startup validation.
- Status: Implemented.

## 37) RBAC Role-Name Heuristic Drift
- Threat: Inferring Kubernetes permissions from role names alone (`cluster-admin`, `view`, etc.) can miss or misstate custom-role privileges.
- Fix: Collect `Role`/`ClusterRole` assets and derive policy statements from concrete RBAC `rules`; keep fallback heuristics only when role data is missing.
- Status: Implemented.

## 38) Secret Value Retention in Repository Leak Findings
- Threat: Repository leak scanning can accidentally persist raw secret values into logs, scan artifacts, or API payloads.
- Fix: Store only secret fingerprints and redacted snippets; never store raw secret values in findings evidence.
- Status: Implemented.

## 39) Unbounded Repository Scan Blast Radius
- Threat: Unbounded repo scans can consume resources or scan out-of-scope repositories in shared environments.
- Fix: Enforce bounded history/findings limits and optional repo allowlist (`IDENTRAIL_REPO_SCAN_ALLOWLIST`) with write-protected API trigger.
- Status: Implemented.

## 40) Repo Scan Data Mixing with Cloud Scan Records
- Threat: Storing repository findings in existing cloud scan tables can break client assumptions and pollute cloud risk workflows.
- Fix: Persist repository scan lifecycle and findings in dedicated tables with dedicated API endpoints.
- Status: Implemented.

## 41) Concurrent Repo Scans on Same Target
- Threat: API-triggered and worker-triggered repo scans on the same target can overlap and produce duplicated workload.
- Fix: Add per-target single-flight lock (`repo-scan:<target>`) and return conflict (`409`) for in-flight target scans.
- Status: Implemented.

## 42) Misconfigured Scheduled Repo Target Scope
- Threat: Worker repo schedule can unintentionally scan out-of-scope repositories.
- Fix: Startup validation enforces explicit target list and allowlist compatibility before worker starts.
- Status: Implemented.

## 43) Multi-Instance Lock Drift
- Threat: Node-local locks allow overlapping scans when API/worker run on multiple instances.
- Fix: Add PostgreSQL advisory lock backend with namespace support (`IDENTRAIL_LOCK_BACKEND`, `IDENTRAIL_LOCK_NAMESPACE`).
- Status: Implemented.

## 44) Unbounded Client-Side List Paging
- Threat: Pulling large full lists for scans/findings can increase latency and memory pressure.
- Fix: Add cursor pagination (`cursor`, `next_cursor`) to list endpoints while preserving backward compatibility.
- Status: Implemented.

## 45) OIDC-Only Deployments Accidentally Running Unauthenticated
- Threat: If API key lists are empty and OIDC auth is configured incorrectly in middleware, `/v1/*` could become unintentionally open.
- Fix: Enforce auth middleware for OIDC-only mode and require a valid verified bearer token when API keys are absent.
- Status: Implemented.

## 46) Inconsistent Write Authorization Across API Keys and OIDC Scopes
- Threat: Mixed auth modes can allow write endpoints without explicit write scope checks.
- Fix: Normalize auth scopes in middleware and enforce write access via `write` scope (or admin) for both scoped keys and OIDC tokens.
- Status: Implemented.

## 47) Graph Semantic Drift
- Threat: New or mistyped relationship names can silently enter storage and break path logic and findings.
- Fix: Validate relationships against an explicit supported semantic contract and enforce fixture-based contract tests.
- Status: Implemented.

## 48) Non-Deterministic Finding Evidence
- Threat: Same scan input can produce evidence in different orders, creating noisy diffs and reducing operator trust.
- Fix: Sort risk evidence deterministically before generating findings and cover with determinism tests.
- Status: Implemented.

## 49) Thundering-Herd Retry Under AWS Throttling
- Threat: Synchronized retries during IAM rate limits can worsen outage duration and throttling pressure.
- Fix: Add bounded jitter to AWS retry backoff.
- Status: Implemented.

## 50) Silent Partial Collector Failures
- Threat: Collector decode/source issues can be dropped silently, leading operators to trust incomplete scan output.
- Fix: Add diagnostic collector contract and surface source errors in scan lifecycle events.
- Status: Implemented.

## 51) Normalized Schema Drift at Runtime
- Threat: Missing/invalid normalized fields can persist malformed entities and break graph/risk logic later.
- Fix: Enforce normalized bundle contract validation before graph resolution and persistence.
- Status: Implemented.

## 52) Graph Edge Drift and Duplicate Semantics
- Threat: Duplicate or invalid relationship edges can inflate privilege paths and cause unstable findings.
- Fix: Enforce graph endpoint contract, relationship ID uniqueness, semantic tuple uniqueness, and required discovery timestamp.
- Status: Implemented.

## 53) Transient Scheduler Failure Drops
- Threat: One transient failure in scheduled runs can cause missed scans without retry.
- Fix: Add bounded scheduler retries with exponential backoff and dead-letter callback on exhaustion.
- Status: Implemented.

## 54) Hidden Degraded Scan Success
- Threat: A scan can complete with partial source failures but still look like a clean success to operators.
- Fix: Emit explicit `partial` lifecycle state and warning events with truncated source-error evidence.
- Status: Implemented.

## 55) API Sort Drift Across Clients
- Threat: Different clients can interpret ordering differently, creating inconsistent findings/scans views.
- Fix: Standardize list sorting with `sort_by` and `sort_order` query parameters across `/v1` list endpoints.
- Status: Implemented.

## 56) Contract Drift Between API and Integrations
- Threat: Endpoint/parameter drift can break dashboard and external automation unexpectedly.
- Fix: Publish and test a versioned OpenAPI v1 contract (`docs/openapi-v1.yaml` + contract tests).
- Status: Implemented.

## 57) Misleading CLI Risk Prioritization
- Threat: Lexical severity ordering can hide highest-severity findings lower in table output.
- Fix: Deterministic severity-rank sorting in CLI table output.
- Status: Implemented.

## 58) Unverified Migration Rollback Path
- Threat: Rollback scripts may exist but fail during incident pressure if never validated.
- Fix: Add explicit down migration runner and integration roundtrip test (`up -> down -> up`).
- Status: Implemented.

## 59) Runtime Regressions Escaping Unit Tests
- Threat: Unit-only CI can miss failures in real command and container startup paths.
- Fix: Add CLI smoke and dockerized API smoke gates in CI.
- Status: Implemented.

## Current Gaps (Next)
- Add encrypted secret management and external KMS guidance.
- Add audit sink forwarding guide for centralized log pipelines.
