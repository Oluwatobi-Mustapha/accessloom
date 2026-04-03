# Repository Exposure Scanner

## Goal

Detect leaked secrets and high-signal misconfigurations in public repository history, without storing raw secret values.

## Command

```bash
identrail repo-scan --repo owner/repo
```

Also supports full URLs and local git paths:

```bash
identrail repo-scan --repo https://github.com/owner/repo.git
identrail repo-scan --repo /path/to/local/repo
```

## API

You can trigger the same scanner through API:

```bash
curl -X POST http://localhost:8080/v1/repo-scans \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <write-enabled-key>" \
  -d '{
    "repository": "owner/repo",
    "history_limit": 500,
    "max_findings": 200
  }'
```

Read APIs:

- `GET /v1/repo-scans`
- `GET /v1/repo-scans/:repo_scan_id`
- `GET /v1/repo-findings?repo_scan_id=&severity=&type=`
- list endpoints support cursor pagination (`?limit=...&cursor=...`) and return `next_cursor` when more results exist

## What It Scans

1. Commit history (all reachable commits, bounded by `--history-limit`):
- Added diff lines are scanned for token/key material.
2. HEAD snapshot:
- IaC/CI/runtime config files are scanned for high-signal misconfig patterns.

## Current Detections

- Secret exposure detectors (history):
  - AWS access key IDs
  - AWS secret-access-key patterns
  - GitHub tokens (`ghp_`, `github_pat_`)
  - Slack tokens
  - Private key headers
- Misconfiguration detectors (HEAD):
  - GitHub Actions `permissions: write-all`
  - GitHub Actions `pull_request_target` trigger
  - Kubernetes `privileged: true`
  - Terraform public S3 ACL
  - Terraform SSH/RDP open to world (`0.0.0.0/0`)
  - Docker `FROM ...:latest`

## Security Guardrails

- Read-only git operations only (`clone --mirror`, `rev-list`, `show`, `ls-tree`).
- Secret values are never stored in findings.
- Evidence keeps only:
  - detector name
  - commit/path/line context
  - secret fingerprint (SHA-256)
  - redacted line snippets
- Findings are deterministic and deduplicated by stable IDs/fingerprints.
- Output is capped by `--max-findings` to prevent runaway payloads.
- Repo scan metadata/findings are persisted in dedicated storage (`repo_scans`, `repo_findings`) to avoid changing existing cloud scan APIs.

## Useful Flags

- `--history-limit` (default: `500`): max commits to inspect.
- `--max-findings` (default: `200`): hard cap on findings.
- `--output table|json`.

## Runtime Configuration

- `IDENTRAIL_REPO_SCAN_ENABLED` (default: `false`)
- `IDENTRAIL_REPO_SCAN_HISTORY_LIMIT` (default: `500`)
- `IDENTRAIL_REPO_SCAN_MAX_FINDINGS` (default: `200`)
- `IDENTRAIL_REPO_SCAN_HISTORY_LIMIT_MAX` (default: `5000`)
- `IDENTRAIL_REPO_SCAN_MAX_FINDINGS_MAX` (default: `1000`)
- `IDENTRAIL_REPO_SCAN_ALLOWLIST`:
  - required when `IDENTRAIL_REPO_SCAN_ENABLED=true`
  - comma-separated list of allowed target patterns
  - supports prefix wildcard with `*` (example: `trusted-org/*`)
  - set `*` only if you intentionally want open target scope
- Optional worker scheduling:
  - `IDENTRAIL_WORKER_REPO_SCAN_ENABLED` (`false` by default)
  - `IDENTRAIL_WORKER_REPO_SCAN_RUN_NOW` (`false` by default)
  - `IDENTRAIL_WORKER_REPO_SCAN_INTERVAL` (`1h` by default)
  - `IDENTRAIL_WORKER_REPO_SCAN_TARGETS` (required when enabled)
  - `IDENTRAIL_WORKER_REPO_SCAN_HISTORY_LIMIT` (`0` means use service default)
  - `IDENTRAIL_WORKER_REPO_SCAN_MAX_FINDINGS` (`0` means use service default)

## Concurrency Behavior

- Cloud scan lock key: `scan:<provider>`
- Repo scan lock key: `repo-scan:<target>`
- If a repo target is already running, API returns `409` and worker logs skip for that target.

## Known Limits

- Focused on high-signal patterns, not exhaustive secret taxonomy.
- Full-history scanning on very large repositories can be expensive; tune `--history-limit`.
- Current version targets public repositories and local clones (no private-repo auth flow yet).
