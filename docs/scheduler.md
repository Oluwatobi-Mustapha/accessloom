# Scheduler and Scan Locking

## Purpose

Prevent overlapping scans and support periodic scan runs.

## Components

- `internal/scheduler/lock.go`: keyed in-memory lock
- `internal/scheduler/postgres_lock.go`: distributed advisory lock backend for multi-instance runs
- `internal/scheduler/runner.go`: periodic loop executor
- `cmd/worker`: process that runs scheduled scans and API queue-drain ticks

## How safety works

- Service lock key: `scan:<provider>`
- If a scan is already running, new trigger is skipped/conflicted
- This protects writes from overlap and duplicate race conditions

## Retry and Dead Letter Behavior

- Runner now supports bounded retries per tick (`MaxAttempts`).
- Retry uses exponential backoff from a configurable base delay (`RetryBackoff`), capped for safety.
- When all retries are exhausted, runner emits a dead-letter callback (`OnDeadLetter`) for operator logging/alert hooks.

## Scan Lifecycle States

Scan event stream now emits explicit states:

- `queued`
- `running`
- `partial` (non-fatal source errors captured)
- `succeeded`
- `failed`
