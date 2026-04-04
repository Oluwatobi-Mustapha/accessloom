# Week 4 Rollout and Enforcement

Week 4 introduces phased enforcement and operating procedures for production rollout.

## Delivered components

- Rollout config with phase controls:
  - `.github/identrail-reviewer/rollout.v1.json`
- Baseline config for new-findings-only mode:
  - `.github/identrail-reviewer/baseline.v1.json`
- Enforcement decision engine:
  - `internal/identrailreviewer/enforcement/enforcement.go`
- Weekly operations report workflow:
  - `.github/workflows/identrail-reviewer-weekly-report.yml`
- PR review workflow gate integration:
  - `.github/workflows/identrail-reviewer-review.yml`

## Rollout model

- `advisory`: findings are reported but no merge blocking.
- `enforced`: protected-path changes can be blocked for configured severities.
- `strict`: blocking severities block regardless of file scope.

## Operational expectations

- Start in `advisory` and gather accuracy metrics.
- Move to `enforced` only after precision and false-positive targets are stable.
- Use `strict` only after sustained quality over multiple release cycles.
- Maintain the baseline file so review comments focus on new regressions, not accepted legacy debt.
- Use inline comments for diff-touched findings to shorten remediation cycle time.
