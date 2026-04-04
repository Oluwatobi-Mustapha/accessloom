# Copilot Autofix Automation for Code Scanning

This repository can automatically generate Copilot Autofix suggestions for open CodeQL alerts, commit the fixes to branches, and open draft pull requests.

Workflow file:
- `.github/workflows/code-scanning-autofix.yml`

## How It Works

1. Finds open CodeQL alerts that match configured severities.
2. Requests an autofix for each alert.
3. Waits for autofix generation to complete.
4. Creates a commit on `autofix/code-scanning-alert-<alert_number>`.
5. Opens a draft PR to `main`.

## Triggers

- Scheduled: weekdays at `02:23 UTC`
- Manual: **Actions** -> **Code Scanning Autofix** -> **Run workflow**

Manual inputs:
- `apply_changes`:
  - `false` = dry run (discovery only)
  - `true` = create commits and PRs
- `max_alerts`: max number of alerts processed in one run
- `severities`: comma-separated list (for example `critical,high`)

## Required Repository Settings

1. Enable GitHub Advanced Security + Code Scanning for the repository.
2. Enable **Copilot Autofix for CodeQL** in Security settings.
3. Ensure Actions workflow permissions allow `Read and write permissions`.

The workflow already requests these token permissions:
- `security-events: write`
- `contents: write`
- `pull-requests: write`

## Safety Notes

- PRs are opened as draft for human review.
- If no suggested fix exists for an alert, that alert is skipped.
- If a PR already exists for an alert branch, the alert is skipped.

## Typical Rollout

1. Merge the workflow PR.
2. Run manual dry-run once (`apply_changes=false`).
3. Run manual apply once (`apply_changes=true`) and review generated PRs.
4. Keep schedule enabled for continuous remediation.
