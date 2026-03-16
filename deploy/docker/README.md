# Docker Deployment

## Files

- `Dockerfile.backend`: builds API or worker image (`TARGET=server|worker`)
- `Dockerfile.web`: builds dashboard web image
- `docker-compose.yml`: local single-host stack
- `.env.example`: environment template

## Quick Start

1. `cp deploy/docker/.env.example deploy/docker/.env`
2. Edit keys and secrets in `deploy/docker/.env`
3. `docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env up -d --build`

## Verify

- API health: `curl http://localhost:8080/healthz`
- Web UI: `http://localhost:8081`
