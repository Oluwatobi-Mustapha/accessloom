# Phase 3: Web Dashboard (Scaffold Start)

## Goal

Create a thin React + TypeScript dashboard shell that can consume Identrail APIs.

## Implemented in this milestone

- Frontend scaffold in `web/`:
  - Vite + React + TypeScript setup
  - API client (`web/src/api/client.ts`)
  - app shell (`web/src/App.tsx`)
- Initial views consume:
  - `GET /v1/findings/summary`
  - `GET /v1/findings/trends`
  - `GET /v1/scans`
  - `GET /v1/findings` (supports `severity`, `type`, `scan_id` filters)
  - `GET /v1/findings/:finding_id` (finding drill-down)
- Dashboard views now include:
  - findings table with live severity/type filters
  - scan selector and scan diff panel with optional baseline scan selection
  - identity/relationship explorer snapshot
  - recent trend list
- Frontend tests:
  - Vitest + Testing Library
  - API client query contract tests
  - App rendering smoke test with mocked API responses

## Next UI slices

1. Full graph path visualization and pivoting by node.
2. Finding remediation workflow and ownership overlays.
3. Historical trend comparisons across date windows.
