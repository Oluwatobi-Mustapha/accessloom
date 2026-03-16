# Scheduler and Idempotent Scan Locking

## Purpose

The scheduler layer prevents overlapping scan executions for the same provider and provides a reusable loop for periodic scans.

## Components

- `internal/scheduler/lock.go`
  - keyed in-memory lock
  - `TryAcquire(key)` returns release function
- `internal/scheduler/runner.go`
  - periodic run loop
  - single-flight execution via lock
  - `ErrAlreadyRunning` when a run is skipped due to lock contention

## API Integration

`internal/api.Service` uses the scheduler lock per provider key (`scan:<provider>`):

- if lock is available, scan proceeds
- if lock is held, API returns conflict (`409`) with `scan already in progress`

This gives idempotent behavior for repeated trigger calls and protects persistence from concurrent duplicate writes.
