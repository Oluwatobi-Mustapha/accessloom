<p align="center">
    <a href="https://github.com/Oluwatobi-Mustapha/identrail"><img src="./docs/static/images/identrail-wordmark.svg" height="100" /></a>
</p>

[![Coverage](https://img.shields.io/badge/coverage-80.2%25-brightgreen?style=for-the-badge)](https://github.com/Oluwatobi-Mustapha/identrail/actions/workflows/ci.yml)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/Oluwatobi-Mustapha/identrail/ci.yml?branch=main&label=tests&style=for-the-badge)](https://github.com/Oluwatobi-Mustapha/identrail/actions/workflows/ci.yml)
![Latest version](https://img.shields.io/github/v/tag/Oluwatobi-Mustapha/identrail?sort=semver&style=for-the-badge&label=Latest%20version)

- Website: https://github.com/Oluwatobi-Mustapha/identrail
- Discussions: https://github.com/Oluwatobi-Mustapha/identrail/discussions
- Documentation Index: [docs/README.md](docs/README.md)
- API Contract: [docs/openapi-v1.yaml](docs/openapi-v1.yaml)
- Enterprise Quickstart: [docs/enterprise-quickstart.md](docs/enterprise-quickstart.md)
- Security Policy: [SECURITY.md](SECURITY.md)


Machine identity security platform for cloud and Kubernetes workloads.

Identrail discovers machine identities and trust paths across AWS and Kubernetes, detects high-signal identity risk findings, scans repositories for exposure risks, and supports centralized authorization with rollout-safe policy controls.

## Getting Started

```bash
cp deploy/docker/.env.example deploy/docker/.env
docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env up -d --build
curl -sS http://localhost:8080/healthz
```

## Development and Quality

```bash
make bootstrap
make ci
```

## Docs and Project Links

- Documentation index: [docs/README.md](docs/README.md)
- API contract: [docs/openapi-v1.yaml](docs/openapi-v1.yaml)
- Enterprise quickstart: [docs/enterprise-quickstart.md](docs/enterprise-quickstart.md)
- Operator readiness: [docs/operator-readiness.md](docs/operator-readiness.md)
- Security policy: [SECURITY.md](SECURITY.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
- Discussions: https://github.com/Oluwatobi-Mustapha/identrail/discussions
