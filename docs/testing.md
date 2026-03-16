# Testing Strategy

## Principles

- Unit tests for core packages and orchestration paths
- Fixture-based tests for provider collection/normalization/rules
- Sqlmock tests for Postgres store behavior
- Scheduler and worker tests for run safety

## Current Focus

- Config defaults and env parsing
- Scoped API key parsing and write authorization behavior
- Scoped read authorization enforcement behavior (`read` or `write`)
- Webhook alerter URL validation, severity filtering, and non-2xx failure handling
- API routes and scan trigger behavior
- API auth and write-authorization middleware behavior
- API rate-limit and audit-log middleware behavior
- Audit sink file export behavior
- Service non-blocking alert callback behavior
- Startup security config validation and warning coverage
- Memory/Postgres persistence logic
- Migration runner behavior
- Artifact and finding idempotent upserts
- Scheduler lock/runner behavior
- Worker startup and cancellation behavior
