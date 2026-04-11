# Deployment Anywhere

This guide standardizes deployment for five common targets:

1. Docker Compose (single host)
2. Kubernetes (cluster)
3. Kubernetes Helm (cluster)
4. Terraform (cluster automation)
5. Linux VM with systemd

## 1) Docker Compose

Use this for quick production-like environments on one host.

Fastest local bootstrap:
- `make quickstart`

1. Copy env template:
   - `cp deploy/docker/.env.example deploy/docker/.env`
2. Edit strong secrets in `deploy/docker/.env`.
   - local dashboard CORS is preconfigured in the template: `IDENTRAIL_CORS_ALLOWED_ORIGINS=http://localhost:8081`
3. Start stack:
   - `docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env up -d --build`
4. Verify:
   - API health: `curl http://localhost:8080/healthz`
   - Web: `http://localhost:8081`

## 2) Kubernetes

Use this for managed cluster deployment.

1. Create namespace and config:
   - `kubectl apply -f deploy/kubernetes/namespace.yaml`
   - `kubectl apply -f deploy/kubernetes/configmap.yaml`
2. Create secret from `deploy/kubernetes/secret.example.yaml` (fill real values first).
3. Apply workloads:
   - `kubectl apply -f deploy/kubernetes/api-deployment.yaml`
   - `kubectl apply -f deploy/kubernetes/api-service.yaml`
   - `kubectl apply -f deploy/kubernetes/worker-deployment.yaml`
4. Optional ingress:
   - `kubectl apply -f deploy/kubernetes/ingress.example.yaml`

## 3) Kubernetes Helm

Use this for upgrade-safe cluster rollout.

1. Copy chart values:
   - `cp deploy/helm/identrail/values.yaml /tmp/identrail-values.yaml`
2. Set production images and secrets in `/tmp/identrail-values.yaml`.
3. Install or upgrade:
   - `helm upgrade --install identrail deploy/helm/identrail -n identrail --create-namespace -f /tmp/identrail-values.yaml`

## 4) Terraform

Use this when infrastructure teams want repeatable IaC rollout.

1. Copy example vars:
   - `cp deploy/terraform/terraform.tfvars.example deploy/terraform/terraform.tfvars`
2. Edit `terraform.tfvars` (image tags, secrets, provider settings).
3. Run:
   - `cd deploy/terraform`
   - `terraform init && terraform apply`

## 5) Linux VM (systemd)

Use this where Kubernetes is not required.

1. Create user and directories:
   - `/opt/identrail` for app files
   - `/etc/identrail/identrail.env` from `deploy/systemd/identrail.env.example`
2. Build and install binaries:
   - `go build -o /usr/local/bin/identrail-server ./cmd/server`
   - `go build -o /usr/local/bin/identrail-worker ./cmd/worker`
3. Copy migrations and fixtures to `/opt/identrail/`.
4. Install systemd units:
   - `cp deploy/systemd/identrail-api.service /etc/systemd/system/`
   - `cp deploy/systemd/identrail-worker.service /etc/systemd/system/`
5. Enable and start:
   - `systemctl daemon-reload`
   - `systemctl enable --now identrail-api identrail-worker`

## Notes

- Current provider collection mode is fixture-based for deterministic scans.
- AWS can now run in fixture mode or live SDK mode (`IDENTRAIL_AWS_SOURCE=sdk`).
- Kubernetes can now run in fixture mode or live kubectl mode (`IDENTRAIL_K8S_SOURCE=kubectl`).
- Repository exposure scans can be run via CLI (`identrail repo-scan`) or API (`POST /v1/repo-scans`).
- Optional continuous repo scanning can run from worker (`IDENTRAIL_WORKER_REPO_SCAN_ENABLED=true` + `IDENTRAIL_WORKER_REPO_SCAN_TARGETS`).
- For tighter safety in shared environments, set `IDENTRAIL_REPO_SCAN_ALLOWLIST`.
- For multi-instance API/worker deployments, use `IDENTRAIL_LOCK_BACKEND=postgres` (or `auto` with database mode).
- For live AWS/Kubernetes scans, use least-privilege templates in `deploy/policies/`.
- Use PostgreSQL in non-local deployments.
- Set HTTPS endpoints for alert/audit forwarding in production.
