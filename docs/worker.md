# Worker

## What it does

The worker runs scans on a schedule.

- Binary: `cmd/worker`
- Loop: `internal/scheduler/runner.go`
- Scan call: `api.Service.RunScan`

## Config

- `IDENTRAIL_SCAN_INTERVAL` (default `15m`)
- `IDENTRAIL_WORKER_RUN_NOW` (default `true`)
- `IDENTRAIL_AWS_FIXTURES`
- `IDENTRAIL_DATABASE_URL`

## Behavior

- Optional scan on startup (`WORKER_RUN_NOW=true`)
- Repeats scans every interval
- Uses same persistence flow as API-triggered scan
- Skips overlapping runs via existing service lock
