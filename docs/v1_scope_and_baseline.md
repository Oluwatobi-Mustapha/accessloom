# V1 Scope And Baseline (First 10 Priorities)

This document locks the first ten non-negotiable V1 priorities.

## 1) Scope Freeze

- Core path: AWS + Kubernetes discovery, normalization, graph, risk findings, API, dashboard.
- Optional module: GitHub repository exposure scanner (`repo-scan`) remains separate from core identity scan flow.
- Provider guardrail: startup validation accepts only `aws` or `kubernetes` for V1 runtime.

## 2) Standards Baseline

- Auth baseline: API key auth plus OIDC/OAuth2-compatible bearer auth (Keycloak-compatible issuer/audience model).
- Finding baseline: typed internal finding model enriched with control references.
- Export baseline:
  - OCSF-aligned payload export
  - AWS Security Finding Format (ASFF) export
- Compliance baseline: each finding type maps to CIS/NIST-style control references in evidence.

## 3) Reliability Hardening

- Idempotent persistence for scans, artifacts, findings, and repo findings.
- Single-flight locking for scan execution (`scan:<provider>`, `repo-scan:<target>`).
- AWS collector retries transient IAM failures with bounded exponential backoff and jitter.
- Partial-failure visibility through scan event stream and explicit failed/completed scan status transitions.

## 4) Data Contract Hardening

- Graph relationship contract is explicit and validated:
  - `can_assume`
  - `attached_policy`
  - `attached_to`
  - `bound_to`
  - `can_access`
  - `can_impersonate`
- Fixture-based contract tests verify normalized identities and relationship types for AWS and Kubernetes pipelines.

## 5) Risk Engine Productionization

- High-value rules in place:
  - admin-equivalent/overprivileged access
  - wildcard/broad trust
  - stale identities
  - ownerless identities
  - escalation paths
- Findings are typed, deterministic, and include evidence + remediation text.
- Evidence ordering is deterministic across reruns to keep diffing stable.

## 6) Collector Reliability Hardening

- Collectors now support partial failure diagnostics through `CollectWithDiagnostics`.
- Kubernetes kubectl collector has bounded retry/backoff/jitter for transient API failures.
- Source-level decode and collection issues are captured as non-fatal diagnostics.
- AWS collector now reports non-fatal source issues (for example malformed role payload shapes) without dropping full scan runs.

## 7) Scheduler + Scan Idempotency

- Scheduler runner now supports bounded retry attempts and exponential backoff.
- Dead-letter callback hook added for exhausted retry paths.
- Scan lifecycle state tracking now emits: `queued`, `running`, `partial`, `succeeded`, `failed`.
- Partial runs are explicit in scan events when source diagnostics are present.

## 8) Normalization Contract Hardening

- Normalized bundle validator now enforces required identity/workload/policy fields.
- Policy normalized payload contract is strict and explicit (`policy_type`, `identity_id`, statement/principal requirements).
- AWS and Kubernetes fixture pipelines are covered by contract tests to prevent schema drift.

## 9) Graph Contract Hardening

- Graph contract validator now enforces:
  - edge type support
  - endpoint integrity by relationship semantic
  - relationship ID uniqueness
  - semantic tuple uniqueness (`type + from + to`)
  - required discovery timestamp on all edges
- AWS and Kubernetes graph snapshots were added as regression fixtures.

## 10) Risk Rule Reliability Baseline

- Rule outputs remain deterministic for identical inputs.
- Evidence and relationship contracts are now validated before rule execution is persisted.
- Regression tests now cover deterministic and stable graph/rule input expectations across providers.
