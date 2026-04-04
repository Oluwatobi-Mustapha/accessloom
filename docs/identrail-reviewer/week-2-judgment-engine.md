# Week 2 Judgment Engine

Week 2 delivers deterministic PR and issue review logic for `identrail-reviewer`.

## Delivered components

- CLI reviewer entrypoint:
  - `cmd/identrail-reviewer/main.go`
- Structured model and output contract usage:
  - `internal/identrailreviewer/model/model.go`
- Pull request review rules:
  - `internal/identrailreviewer/review/pr.go`
- Issue triage review rules:
  - `internal/identrailreviewer/review/issue.go`
- Utility parsing helpers:
  - `internal/identrailreviewer/review/util.go`
- Active review workflow with PR/issue comment upsert:
  - `.github/workflows/identrail-reviewer-review.yml`

## Review behavior

- Deterministic workflow checks for release and permissions regressions.
- PR template completeness validation.
- Issue template completeness validation.
- Public sensitive-data exposure detection in issue bodies.
- Structured findings with severity, confidence, rationale, and recommendation.

## Guardrails

- Findings are deterministic and evidence-based.
- If issue type cannot be inferred safely, reviewer abstains on that classification.
- Comments are updated in-place to avoid review spam.
