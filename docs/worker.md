# Worker

## What it does

The worker runs scans on a schedule.

- Binary: `cmd/worker`
- Loop: `internal/scheduler/runner.go`
- Scan call: `api.Service.RunScan`
- Optional repo scan call: `api.Service.RunRepoScanPersisted`

## Config

- `IDENTRAIL_SCAN_INTERVAL` (default `15m`)
- `IDENTRAIL_WORKER_RUN_NOW` (default `true`)
- `IDENTRAIL_AWS_FIXTURES`
- `IDENTRAIL_DATABASE_URL`
- `IDENTRAIL_WORKER_REPO_SCAN_ENABLED` (default `false`)
- `IDENTRAIL_WORKER_REPO_SCAN_RUN_NOW` (default `false`)
- `IDENTRAIL_WORKER_REPO_SCAN_INTERVAL` (default `1h`)
- `IDENTRAIL_WORKER_REPO_SCAN_TARGETS` (comma-separated repos, required when enabled)
- `IDENTRAIL_WORKER_REPO_SCAN_HISTORY_LIMIT` (optional override; `0` uses service default)
- `IDENTRAIL_WORKER_REPO_SCAN_MAX_FINDINGS` (optional override; `0` uses service default)

## Behavior

- Optional scan on startup (`WORKER_RUN_NOW=true`)
- Repeats scans every interval
- Uses same persistence flow as API-triggered scan
- Skips overlapping runs via existing service lock
- Optional repo scan scheduler is additive and disabled by default
- Repo scans use per-target lock key (`repo-scan:<target>`) to avoid overlap between API and worker triggers
