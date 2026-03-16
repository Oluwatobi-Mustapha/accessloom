# Threat Model

Simple threat list for current system.

## 1) Overlapping Scan Runs
- Threat: Two scans write at same time and cause inconsistent results.
- Fix: Single-flight lock per provider (`scan:<provider>`).
- Status: Implemented.

## 2) Duplicate Data on Rerun
- Threat: Re-running same flow keeps inserting duplicates.
- Fix: Upsert keys for raw assets, identities, policies, relationships, permissions, findings.
- Status: Implemented.

## 3) Broad Trust + Broad Permission Escalation
- Threat: External principal can assume role with admin-like permissions.
- Fix: Risk engine rule for escalation path and risky trust findings.
- Status: Implemented.

## 4) API Trigger Abuse
- Threat: Repeated scan trigger calls can overload service.
- Fix: Single-flight lock and API conflict response for in-flight run.
- Status: Implemented.

## 5) Unbounded List Queries
- Threat: Very high `limit` may cause performance issues.
- Fix: Clamp API `limit` with max cap.
- Status: Implemented.

## 6) Missing Security Response Headers
- Threat: Weak default API hardening.
- Fix: Add API security headers middleware.
- Status: Implemented.

## 7) Unauthenticated API Access
- Threat: Anyone can trigger scans or read findings.
- Fix: API key authentication for `/v1/*` endpoints.
- Status: Implemented.

## 8) Unauthorized Scan Trigger
- Threat: Read-only API key can still trigger write actions.
- Fix: Dedicated write authorization key list for `POST /v1/scans`.
- Status: Implemented.

## 9) Excessive Request Flood
- Threat: Repeated requests can degrade API availability.
- Fix: Per-IP rate limiter.
- Status: Implemented.

## 10) Missing API Audit Trail
- Threat: Hard to investigate who called sensitive endpoints.
- Fix: API audit log middleware on `/v1/*`.
- Status: Implemented.

## 11) Misconfigured Database Connection Pool
- Threat: Too many DB connections or long-lived bad connections.
- Fix: Set safe Postgres pool defaults.
- Status: Implemented.

## 12) Schema Drift on Startup
- Threat: Service starts on old schema and fails at runtime.
- Fix: Startup migration runner for Postgres mode.
- Status: Implemented.

## 13) Scope Confusion in API Key Authorization
- Threat: Mixed legacy key lists and scoped keys can produce wrong access behavior.
- Fix: Scoped key map takes precedence when configured (`IDENTRAIL_API_KEY_SCOPES`).
- Status: Implemented.

## 14) Missing Durable Audit Export
- Threat: Request logs in process output can be lost during log rotation or collection issues.
- Fix: Optional JSONL audit file sink (`IDENTRAIL_AUDIT_LOG_FILE`) with append-only writes.
- Status: Implemented.

## Current Gaps (Next)
- Add encrypted secret management and key rotation runbook.
- Add audit sink forwarding guide for centralized log pipelines.
