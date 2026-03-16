# Testing Strategy

## Principles

- Unit tests for every core package and orchestration path
- Fixture-based tests for provider payload normalization and collection behavior
- Integration tests against Postgres in Phase 2
- Mock provider dependencies for deterministic rule testing

## Current Coverage Focus

- Config loading and defaults
- Domain validation behavior
- Telemetry setup and instrumentation behavior
- API routing health and scan schedule endpoints
- Scan orchestration success and failure paths
- AWS collector pagination, throttling retries, dedup idempotency, and cancellation handling
- AWS normalizer and graph behavior (trust parsing, permission expansion, relationship materialization)
