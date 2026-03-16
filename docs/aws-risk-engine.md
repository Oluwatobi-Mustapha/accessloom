# AWS Risk Engine (Phase 1)

## Purpose

The AWS risk engine evaluates normalized identities and graph relationships to produce typed, explainable findings.

## Findings Implemented

- `overprivileged_identity`
- `risky_trust_policy`
- `escalation_path`
- `stale_identity`
- `ownerless_identity`

## Rule Inputs

- Normalized identities from the AWS normalizer
- Relationship edges from the graph builder (`can_assume`, `can_access`, `attached_policy`)

## Detection Logic (v1)

- Overprivileged: wildcard/admin-capable actions or wildcard resources
- Risky trust: wildcard or cross-account trust principals
- Escalation path: risky trust combined with escalation-capable access
- Stale: last used (or created) exceeds threshold (default 90 days)
- Ownerless: no owner hint present

## Design Decisions

- Deterministic finding IDs to keep reruns idempotent
- Severity ordering is stable (`critical` -> `high` -> `medium` ...)
- Evidence-first findings with machine-readable context and clear remediation text
- Encoded access nodes to avoid ARN delimiter parsing issues

## Tunables

- `WithStaleAfter(duration)`
- `WithRuleClock(nowFunc)`
