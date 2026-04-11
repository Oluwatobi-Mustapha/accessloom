# Docker Deployment

## Files

- `Dockerfile.backend`: builds API or worker image (`TARGET=server|worker`)
- `Dockerfile.web`: builds dashboard web image
- `docker-compose.yml`: local single-host stack
- `.env.example`: environment template

## Quick Start

Fastest local onboarding:

1. `make quickstart`

Manual setup:

1. `cp deploy/docker/.env.example deploy/docker/.env`
2. Edit keys and secrets in `deploy/docker/.env`
   - set `IDENTRAIL_POSTGRES_PASSWORD` to a strong value
   - local dashboard CORS is enabled by default via `IDENTRAIL_CORS_ALLOWED_ORIGINS=http://localhost:8081`
   - for live k8s collection: set `IDENTRAIL_K8S_SOURCE=kubectl`
   - optional context override: `IDENTRAIL_KUBE_CONTEXT`
3. `docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env up -d --build`

## Verify

- API health: `curl http://localhost:8080/healthz`
- Web UI: `http://localhost:8081`
