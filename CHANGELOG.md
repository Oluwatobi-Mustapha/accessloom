# Changelog

## Unreleased
- Added ADR record file (`docs/ADR.md`).
- Added simple threat model (`docs/threat_model.md`).
- Added API security hardening (headers, bounded limits, scan timeout).

## 2026-03-16
- Phase 1 foundation completed.
- AWS collector, normalizer, graph, risk engine, and CLI workflow completed.
- Project renamed to `identrail`.
- Phase 2 started: migrations, store layer, persistence-backed API.
- Scheduler lock and single-flight scan trigger support added.
- Full artifact persistence (raw + normalized + findings) added.
