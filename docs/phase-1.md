# Phase 1: AWS Core Scanner

## Goal

Deliver a usable AWS scanner that collects IAM identity data, normalizes relationships, and produces typed findings for overprivilege, escalation paths, risky trust relationships, staleness, and missing ownership.

## User Stories

- As a cloud security engineer, I can run a scan and get a list of risky identities.
- As an IAM admin, I can understand why a finding exists and how to remediate it.
- As a DevSecOps engineer, I can re-run scans safely without corrupting historical data.

## Scope

- AWS collector for IAM roles, policies, and trust relationships
- Normalized domain mapping
- Graph edge construction (`can_assume`, `attached_policy`, `can_access`)
- Deterministic risk rules for core identity risks
- CLI commands for `scan` and `findings`

## Out of Scope (Phase 1)

- Automated remediation
- SIEM integrations
- Multi-tenant RBAC
- AI-generated recommendations

## Milestone Status

1. Foundation: completed
   - modular monolith skeleton
   - typed domain contracts
   - telemetry hooks and baseline API/CLI
2. AWS Collector: completed
   - IAM role collection with pagination
   - retry/backoff for throttling and transient failures
   - idempotent deduplication by role ARN
   - fixture-based and edge-case unit tests
3. Normalizer + Graph: completed
   - role normalization into provider-agnostic identities and policies
   - permission tuple expansion for analysis
   - trust + attachment + access relationship generation
   - deterministic IDs and deduplication for idempotent reruns
4. Risk Engine: completed
   - typed findings: overprivileged, risky trust, escalation, stale, ownerless
   - deterministic finding IDs and stable severity ordering
   - evidence-rich and remediation-focused output shape
5. CLI UX pass: next

## Phase Diagram

```text
[AWS IAM APIs] --> [Collector] --> [Normalizer] --> [Graph] --> [Risk Rules] --> [Findings Output]
```
