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
- Status: Implemented in this step.

## 6) Missing Security Response Headers
- Threat: Weak default API hardening.
- Fix: Add API security headers middleware.
- Status: Implemented in this step.

## 7) Stale and Ownerless Identities
- Threat: Forgotten identities increase breach surface.
- Fix: Risk rules for stale and ownerless identity findings.
- Status: Implemented.

## 8) Misconfigured Database Connection Pool
- Threat: Too many DB connections or long-lived bad connections.
- Fix: Set safe Postgres pool defaults.
- Status: Planned next hardening step.

## Current Gaps (Next)
- Add authn/authz for API endpoints.
- Add encryption-at-rest + key management guidance for sensitive fields.
- Add audit log stream for access and scan triggers.
- Add production rate limiter (not only lock conflict).
