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

## Useful Flags

- `--history-limit` (default: `500`): max commits to inspect.
- `--max-findings` (default: `200`): hard cap on findings.
- `--output table|json`.

## Known Limits

- Focused on high-signal patterns, not exhaustive secret taxonomy.
- Full-history scanning on very large repositories can be expensive; tune `--history-limit`.
- Current version targets public repositories and local clones (no private-repo auth flow yet).
