# ADR (Architecture Decision Record)

This file tracks major decisions in simple terms.

## ADR-001: Modular Monolith First
- Date: 2026-03-16
- Decision: Start as one deployable service with clean internal modules.
- Why: Faster shipping, easier debugging, less early complexity.
- Tradeoff: Less independent scaling per module at first.

## ADR-002: AWS-First Scope
- Date: 2026-03-16
- Decision: Build full AWS pipeline first. Keep Kubernetes/Azure interfaces ready.
- Why: Smaller scope, faster value, lower risk.
- Tradeoff: Multi-cloud comes later.

## ADR-003: Keep Raw + Normalized Data
- Date: 2026-03-16
- Decision: Store raw provider payloads and normalized entities.
- Why: Better audit trail, better explainability for findings.
- Tradeoff: More storage use.

## ADR-004: Typed Findings
- Date: 2026-03-16
- Decision: Use typed findings (`overprivileged`, `risky_trust`, etc.).
- Why: Easier filtering, stable API contract, clearer remediation.
- Tradeoff: Rule updates need strict schema discipline.

## ADR-005: Idempotent Persistence
- Date: 2026-03-16
- Decision: Use scan-scoped upsert keys for artifacts and findings.
- Why: Safe reruns, no duplicate data growth.
- Tradeoff: More careful key design.

## ADR-006: Single-Flight Scan Lock
- Date: 2026-03-16
- Decision: Reject overlapping scans for same provider.
- Why: Prevent race conditions and duplicate writes.
- Tradeoff: Concurrent trigger requests can return conflict (`409`).

## ADR-007: Memory Store + Postgres Store
- Date: 2026-03-16
- Decision: Keep one store interface with in-memory and Postgres adapters.
- Why: Easy local dev, production-ready path.
- Tradeoff: Two adapters to maintain.
