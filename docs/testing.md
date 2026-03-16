# Testing Strategy

## Principles

- Unit tests for core packages and orchestration paths
- Fixture-based tests for provider collection/normalization/rules
- Sqlmock tests for Postgres store behavior
- Scheduler and worker tests for run safety

## Current Focus

- Config defaults and env parsing
- Scoped API key parsing and write authorization behavior
- API routes and scan trigger behavior
- API auth and write-authorization middleware behavior
- API rate-limit and audit-log middleware behavior
- Audit sink file export behavior
- Memory/Postgres persistence logic
- Migration runner behavior
- Artifact and finding idempotent upserts
- Scheduler lock/runner behavior
- Worker startup and cancellation behavior
