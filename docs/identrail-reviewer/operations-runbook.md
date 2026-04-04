# identrail-reviewer Operations Runbook

## SLO targets

- PR review latency p95: <= 90 seconds for typical PR size.
- High-severity precision (P0/P1): >= 95% on replay benchmark.
- False-positive rate overall: <= 8%.

## Incident response

1. Detection: identify spike in workflow failures, bad comments, or merge blocks.
2. Containment: set rollout phase to `advisory` in `.github/identrail-reviewer/rollout.v1.json`.
3. Verification: replay benchmark cases and compare recent audit artifacts.
4. Recovery: patch rules/policy and restore previous phase only after validation.

## Change management

- Policy and rollout changes must be reviewed via pull request.
- Every rollout phase change should include a rationale in PR description.
- Weekly report artifacts should be inspected for trend breaks.
- Baseline updates (`.github/identrail-reviewer/baseline.v1.json`) should include explicit rationale for each newly ignored finding ID.

## Baseline workflow

1. Capture reviewer artifacts from recent successful runs.
2. Add only explicitly accepted legacy findings to `known_finding_ids`.
3. Re-run reviewer checks and confirm no unexpected new suppressions.
4. Keep baseline review-owned and update it as debt is paid down.
