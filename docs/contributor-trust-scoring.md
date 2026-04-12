# Contributor Trust Scoring (Good Egg)

Identrail runs Good Egg on pull requests to provide an advisory trust signal for the PR author.

Workflow:
- `.github/workflows/good-egg-trust.yml`

## What it does

- Scores every PR author on each workflow run.
- Posts a PR comment and check run with the trust result.
- Applies a single trust label on the PR:
  - `trust/high`
  - `trust/medium`
  - `trust/low`
  - `trust/unknown`
  - `trust/bot`

This signal is advisory by default (`fail-on-low=false`). It is meant to support triage, not replace code review.

## Trigger

- `pull_request_target` on: `opened`, `reopened`, `synchronize`, `ready_for_review`.

## Operational guidance

- Treat `trust/low` and `trust/unknown` as "review deeper" indicators.
- Do not auto-merge based on trust labels alone.
- Keep branch protection tied to core CI and security checks.
