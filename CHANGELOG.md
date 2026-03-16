# Changelog

## Unreleased
- Added worker process for scheduled scans (`cmd/worker`).
- Added shared runtime service bootstrap (`internal/runtime`).
- Added worker scheduling config (`IDENTRAIL_SCAN_INTERVAL`, `IDENTRAIL_WORKER_RUN_NOW`).
- Kept self assessment short and milestone-based (`docs/self_assessment.md`).

## 2026-03-16
- Phase 1 foundation completed.
- AWS collector, normalizer, graph, risk engine, and CLI workflow completed.
- Project renamed to `identrail`.
- Phase 2 started: migrations, store layer, persistence-backed API.
- Scheduler lock and single-flight scan trigger support added.
- Full artifact persistence (raw + normalized + findings) added.
- ADR, threat model, and baseline security hardening added.
