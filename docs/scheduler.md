# Scheduler and Scan Locking

## Purpose

Prevent overlapping scans and support periodic scan runs.

## Components

- `internal/scheduler/lock.go`: keyed in-memory lock
- `internal/scheduler/runner.go`: periodic loop executor
- `cmd/worker`: process that runs scheduled scans

## How safety works

- Service lock key: `scan:<provider>`
- If a scan is already running, new trigger is skipped/conflicted
- This protects writes from overlap and duplicate race conditions
