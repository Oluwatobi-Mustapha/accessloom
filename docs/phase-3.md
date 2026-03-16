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

## Next UI slices

1. Findings table with severity/type filters.
2. Scan diff explorer panel.
3. Identity + relationship explorer views.
