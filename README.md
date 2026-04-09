# I D E N T R A I L

- Website: https://github.com/Oluwatobi-Mustapha/identrail
- Discussions: https://github.com/Oluwatobi-Mustapha/identrail/discussions
- Documentation Index: [docs/README.md](docs/README.md)
- API Contract: [docs/openapi-v1.yaml](docs/openapi-v1.yaml)
- Enterprise Quickstart: [docs/enterprise-quickstart.md](docs/enterprise-quickstart.md)
- Security Policy: [SECURITY.md](SECURITY.md)

[![CI](https://img.shields.io/github/actions/workflow/status/Oluwatobi-Mustapha/identrail/ci.yml?branch=main&label=ci)](https://github.com/Oluwatobi-Mustapha/identrail/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/Oluwatobi-Mustapha/identrail/codeql.yml?branch=main&label=codeql)](https://github.com/Oluwatobi-Mustapha/identrail/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/tag/Oluwatobi-Mustapha/identrail?sort=semver&label=release)](https://github.com/Oluwatobi-Mustapha/identrail/releases)
[![Coverage Gate](https://img.shields.io/badge/coverage%20gate-%E2%89%A580%25-brightgreen)](https://github.com/Oluwatobi-Mustapha/identrail/actions/workflows/ci.yml)

Identrail is a machine identity security platform for cloud and Kubernetes workloads. It discovers identities and trust paths, detects risky access patterns, and supports operator-safe remediation workflows.

The key features of Identrail are:

- **Identity Discovery and Risk Detection**: Collects identity data from AWS and Kubernetes, builds relationships, and produces typed findings with remediation guidance.

- **Repository Exposure Scanning**: Scans repository history and configuration for secret exposure and misconfiguration risks, with bounded scan controls and allowlists.

- **Centralized Authorization**: Enforces tenant/workspace isolation and a strict policy decision order (`tenant_isolation -> rbac -> abac -> rebac -> default_deny`) with simulation, staged rollout, and rollback controls.

- **Operational Safety and Auditability**: Provides decision audit logging, rollout metrics, and runbooks for secure operations and compliance evidence workflows.

- **Portable Deployment and Release Pipeline**: Includes Docker, Kubernetes, Helm, and Terraform deployment assets with CI, CodeQL, release automation, and supply-chain trust artifacts.

For more information, refer to the [documentation index](docs/README.md).

## Getting Started & Documentation

Documentation is available in this repository:

- [Documentation Index](docs/README.md)
- [Enterprise 5-Minute Quickstart](docs/enterprise-quickstart.md)
- [Operator Readiness](docs/operator-readiness.md)
- [Deploy Runbook](docs/deploy-runbook.md)
- [AuthZ Operator Runbook](docs/authz-operator-runbook.md)
- [AuthZ Policy Rollout Runbook](docs/authz-policy-rollout-runbook.md)

If you want a fast local start:

```bash
cp deploy/docker/.env.example deploy/docker/.env
docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env up -d --build
curl -sS http://localhost:8080/healthz
```

## Developing Identrail

This repository contains Identrail core runtime and developer tooling, including:

- API server (`cmd/server`)
- background worker (`cmd/worker`)
- operator/developer CLI (`cmd/cli`)
- repository-native reviewer engine (`cmd/identrail-reviewer`)
- web dashboard (`web/`)

To learn more about compiling Identrail and contributing suggested changes, refer to:

- [Contributing Guide](CONTRIBUTING.md)
- [Development Workflow](docs/development-workflow.md)
- [Testing Strategy](docs/testing.md)

Core local checks:

```bash
make bootstrap
make ci
```

