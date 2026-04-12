# Kubernetes Deployment

## Files

- `namespace.yaml`
- `configmap.yaml`
- `secret.example.yaml`
- `migration-job.yaml`
- `api-deployment.yaml`
- `api-service.yaml`
- `worker-deployment.yaml`
- `ingress.example.yaml`

## Quick Start

1. Apply namespace and config:
   - `kubectl apply -f deploy/kubernetes/namespace.yaml`
   - `kubectl apply -f deploy/kubernetes/configmap.yaml`
2. Create and apply a real secret from `secret.example.yaml`.
3. Run migrations once and wait for completion:
   - `kubectl apply -f deploy/kubernetes/migration-job.yaml`
   - `kubectl -n identrail wait --for=condition=complete --timeout=300s job/identrail-migrations`
4. Apply API + worker:
   - `kubectl apply -f deploy/kubernetes/api-deployment.yaml`
   - `kubectl apply -f deploy/kubernetes/api-service.yaml`
   - `kubectl apply -f deploy/kubernetes/worker-deployment.yaml`
5. Optional ingress:
   - `kubectl apply -f deploy/kubernetes/ingress.example.yaml`

Notes:
- Default manifest profile is production-oriented and fails fast on fixture collectors (`IDENTRAIL_REQUIRE_LIVE_SOURCES=true`).
- Keep `IDENTRAIL_AWS_SOURCE=sdk` and `IDENTRAIL_K8S_SOURCE=kubectl` for production runs.
- For upgrade-safe deployment at scale, prefer Helm (`deploy/helm/identrail`).
