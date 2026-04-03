# Troubleshooting Playbook

## Scan Fails Immediately

Checks:
1. `IDENTRAIL_PROVIDER` is `aws` or `kubernetes`.
2. Auth exists (API keys/scoped keys or OIDC).
3. For AWS SDK mode, credentials and region are valid.
4. For Kubernetes kubectl mode, context and cluster access are valid.

## Frequent Partial Runs

Checks:
1. Inspect `GET /v1/scans/{scan_id}/events` for source errors.
2. Check provider rate limits and transient API failures.
3. Confirm collector retry/backoff settings are active.

## API `409 scan already in progress`

Checks:
1. Confirm long-running scan status in `/v1/scans`.
2. Validate lock backend:
   - multi-instance should use `IDENTRAIL_LOCK_BACKEND=postgres`.
3. Verify same namespace for lock keys (`IDENTRAIL_LOCK_NAMESPACE`).

## No Findings Returned

Checks:
1. Confirm scan completed and not failed.
2. Validate filters (`severity`, `type`, `scan_id`) are not too strict.
3. Run without filters and inspect findings summary.

## Repo Scan Rejected

Checks:
1. `IDENTRAIL_REPO_SCAN_ENABLED=true`.
2. `IDENTRAIL_REPO_SCAN_ALLOWLIST` is set and includes the target.
3. API target is remote (`owner/repo`, `https://...`, or `ssh://...`) and not a local filesystem path.
4. Request uses write-authorized API key/scope.
