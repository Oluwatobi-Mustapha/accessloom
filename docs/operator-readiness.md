# Operator Readiness

This is the handoff guide for running Identrail in production-like environments.

## Install Paths

Choose one:
- Docker Compose: `deploy/docker/`
- Kubernetes manifests: `deploy/kubernetes/`
- Kubernetes Helm: `deploy/helm/`
- Terraform + Helm: `deploy/terraform/`

Primary docs:
- `docs/deployment-anywhere.md`
- `docs/deploy-runbook.md`
- `docs/security-hardening.md`
- `docs/observability.md`
- `docs/enterprise-quickstart.md`
- `docs/authz-operator-runbook.md`
- `docs/authz-policy-rollout-runbook.md`

## Minimum Production Checklist

1. Auth enabled (OIDC or strong API keys).
2. PostgreSQL configured and migrations applied.
3. Lock backend set to `postgres` for multi-instance deploys.
4. Audit sink configured.
5. Alert webhook configured for high/critical findings.
6. Least-privilege AWS/Kubernetes scanner identities in place.

## V1 Done Handoff Checklist

1. Deterministic scans validated on target environments.
2. `/v1` API contract tested by client integrations.
3. CI gates passing (quality, tests, coverage, integration, web build).
4. Threat model and ADR up to date.
5. Runbooks available to on-call team.
6. AuthZ decision audit logging verified (`authz.stage`, `authz.reason`, policy metadata).
