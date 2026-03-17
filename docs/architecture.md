# Identrail Architecture

## Why This Shape

Identrail starts as a modular monolith so we can ship quickly, debug easily, and maintain strict domain boundaries. Every module has one responsibility and communicates through typed contracts.

## Module Layout

- `ingestion`: provider collectors for read-only cloud data pulls
- `normalization`: provider-specific translation into normalized domain entities
- `graph`: relationship construction and path traversal support
- `analysis`: deterministic risk rules over normalized data + graph edges
- `findings`: typed finding lifecycle and remediation metadata
- `ownership`: owner inference and confidence scoring
- `repoexposure`: repository history and HEAD exposure scanner for secret leaks and IaC/CI misconfigurations
- `api`: REST endpoints for scans and findings
- `db`: persistence adapters (memory + postgres)
- `scheduler`: idempotent scan orchestration
- `telemetry`: logging, metrics, and tracing

## Data Flow

```text
Collector -> Raw Assets -> Normalizer -> Domain Entities
                |                           |
                v                           v
            Raw Storage                Graph Builder
                                            |
                                            v
                                      Risk Rule Engine
                                            |
                                            v
                                   Store (Scans/Findings)
                                            |
                                            v
                                          API/CLI
```

## Core Design Decisions

- Provider abstraction via interfaces (`Collector`, `Normalizer`, `RiskRuleSet`) keeps AWS/K8s/Azure implementations isolated.
- Idempotency is a first-class requirement for every scan stage to avoid duplicated records and scan drift.
- Raw and normalized data are both preserved for auditability and rule explainability.
- Repository exposure scans persist in dedicated repo scan tables to avoid coupling with cloud scan records.
- Observability is integrated from day one with structured logs, Prometheus metrics, and tracing hooks.
- Persistence supports local memory mode and PostgreSQL mode behind a single store interface.
- Scan execution persists both raw and normalized artifacts for auditability and explainability.
- Postgres read paths are moving to typed query contracts first, then full sqlc generation.

## Initial Runtime Components

- `cmd/server`: REST API process for health, scans, and findings endpoints.
- `cmd/cli`: operator-focused scanner interface.
- `cmd/worker`: scheduled scan process for periodic runs.
- `internal/app.Scanner`: deterministic scan execution pipeline.
- `internal/api.Service`: scan orchestration + persistence bridge.
- `internal/db`: storage adapters and migration-backed schema.
- `internal/runtime`: shared service bootstrap used by server and worker.
- `internal/providers/aws`: AWS phase-1 provider pipeline (collector -> normalizer -> graph -> rules).
- `internal/providers/kubernetes`: Kubernetes phase-4 pipeline with fixture/kubectl collection, RBAC role-rule normalization, graph, and risk rules.
- `internal/repoexposure`: read-only git history and HEAD scanner with redacted evidence output.

## Future Extraction Plan

When scale demands it:

1. Extract scheduler into a separate worker service.
2. Move ingestion to a queue-driven worker model.
3. Retain API + read model in a dedicated service.
