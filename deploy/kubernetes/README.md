# Kubernetes Deployment

## Files

- `namespace.yaml`
- `configmap.yaml`
- `secret.example.yaml`
- `api-deployment.yaml`
- `api-service.yaml`
- `worker-deployment.yaml`
- `ingress.example.yaml`

## Quick Start

1. Apply namespace and config:
   - `kubectl apply -f deploy/kubernetes/namespace.yaml`
   - `kubectl apply -f deploy/kubernetes/configmap.yaml`
2. Create and apply a real secret from `secret.example.yaml`.
3. Apply API + worker:
   - `kubectl apply -f deploy/kubernetes/api-deployment.yaml`
   - `kubectl apply -f deploy/kubernetes/api-service.yaml`
   - `kubectl apply -f deploy/kubernetes/worker-deployment.yaml`
4. Optional ingress:
   - `kubectl apply -f deploy/kubernetes/ingress.example.yaml`

Notes:
- Default config uses fixture mode (`IDENTRAIL_K8S_SOURCE=fixture`).
- For live cluster collection, set `IDENTRAIL_K8S_SOURCE=kubectl` in `configmap.yaml`.
- For upgrade-safe deployment at scale, prefer Helm (`deploy/helm/identrail`).
