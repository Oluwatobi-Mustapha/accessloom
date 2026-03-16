# Testing Strategy

## Principles

- Unit tests for core packages and orchestration paths
- Fixture-based tests for provider collection/normalization/rules
- Sqlmock tests for Postgres store behavior
- Scheduler and worker tests for run safety

## Current Focus

- Config defaults and env parsing
- API routes and scan trigger behavior
- Memory/Postgres persistence logic
- Artifact and finding idempotent upserts
- Scheduler lock/runner behavior
- Worker startup and cancellation behavior
