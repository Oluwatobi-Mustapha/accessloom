# I D E N T R A I L

[![CI](https://img.shields.io/github/actions/workflow/status/Oluwatobi-Mustapha/identrail/ci.yml?branch=main&label=ci)](https://github.com/Oluwatobi-Mustapha/identrail/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/Oluwatobi-Mustapha/identrail/codeql.yml?branch=main&label=codeql)](https://github.com/Oluwatobi-Mustapha/identrail/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/tag/Oluwatobi-Mustapha/identrail?sort=semver&label=release)](https://github.com/Oluwatobi-Mustapha/identrail/releases)

Identrail is a machine-identity security platform for cloud and Kubernetes workloads.  
It discovers identities and trust paths, detects risky access patterns, and supports operator-safe remediation workflows.

## Why teams use Identrail

- Discover machine identities, relationships, and ownership signals from AWS and Kubernetes.
- Detect high-signal identity risk findings with remediation guidance.
- Scan repository history and configuration for secret exposure and misconfiguration risks.
- Enforce scoped, centralized authorization with tenant/workspace isolation and default-deny behavior.
- Operate safely with rollout controls, simulation, rollback, and decision audit logging.

## What is in this repository

- `cmd/server`: HTTP API service (`/healthz`, `/metrics`, `/v1/*`)
- `cmd/worker`: scheduled scan worker and queue processor
- `cmd/cli`: operator/developer CLI (`scan`, `findings`, `repo-scan`, `authz rollback`)
- `cmd/identrail-reviewer`: repo-native PR/issue reviewer engine
- `internal/`: core scanner, API/authz, storage, providers, telemetry, scheduler
- `web/`: React dashboard
- `deploy/`: Docker, Helm, Kubernetes, systemd, Terraform deployment assets
- `docs/`: runbooks, policy/security docs, release and support docs

## 60-second local start

```bash
cp deploy/docker/.env.example deploy/docker/.env
```

Set strong keys in `deploy/docker/.env`:
- `IDENTRAIL_API_KEYS`
- `IDENTRAIL_WRITE_API_KEYS`
- optional scoped model: `IDENTRAIL_API_KEY_SCOPES`

Start the stack:

```bash
docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env up -d --build
```

Smoke check:

```bash
curl -sS http://localhost:8080/healthz
curl -sS http://localhost:8080/v1/findings?limit=5 -H "X-API-Key: <read-or-admin-key>"
```

Stop:

```bash
docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env down
```

## API surface (v1)

Core endpoints:
- Findings: list, detail, summary, trends, triage, exports
- Scans: enqueue, list, diff, events
- Explorer: identities, relationships, ownership signals
- Repository scans: enqueue/list/detail findings
- AuthZ ops: policy simulation and rollback

Contract:
- `docs/openapi-v1.yaml`

## Security and authorization model

- API key and OIDC auth paths with explicit scope handling (`read`, `write`, `admin`).
- Tenant/workspace request scoping with strict boundary checks.
- Central decision order:
  - `tenant_isolation -> rbac -> abac -> rebac -> default_deny`
- Policy lifecycle controls:
  - persisted policy bundles
  - staged rollout modes (`disabled`, `shadow`, `enforce`)
  - simulation endpoint with full stage trace
  - one-call rollback endpoint/CLI
- Audit events include authz decision metadata with hashed subject/resource IDs.

Runbooks:
- `docs/authz-operator-runbook.md`
- `docs/authz-policy-rollout-runbook.md`
- `docs/security-hardening.md`

## Build and test

```bash
make bootstrap
make ci
```

Or task runner:

```bash
task bootstrap
task ci
```

CI gates include:
- gofmt + `go vet`
- Go tests with coverage threshold
- Postgres integration tests
- Web tests/build
- Infra validation (Helm/Terraform)
- Deploy portability smoke checks

## Deployment paths

- Docker Compose: `deploy/docker/`
- Kubernetes manifests: `deploy/kubernetes/`
- Helm chart: `deploy/helm/identrail/`
- Terraform (Helm-based): `deploy/terraform/`
- systemd services: `deploy/systemd/`

Operator start points:
- `docs/enterprise-quickstart.md`
- `docs/operator-readiness.md`
- `docs/deploy-runbook.md`
- `docs/troubleshooting.md`

## Releases and supply chain trust

- Release automation:
  - `.github/workflows/release.yml`
  - `docs/release-pipeline.md`
- SBOM, attestations, and signing:
  - `.github/workflows/supply-chain-trust.yml`
  - `docs/supply-chain-trust.md`
- Version/support policy:
  - `docs/versioning-support-policy.md`

## Documentation map

Documentation index:
- `docs/README.md`

## Community and governance

- Discussions: https://github.com/Oluwatobi-Mustapha/identrail/discussions
- Contributing: `CONTRIBUTING.md`
- Security policy: `SECURITY.md`
- Code of conduct: `CODE_OF_CONDUCT.md`
- Funding/sponsorship: `.github/FUNDING.yml`
