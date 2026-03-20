# Helm Deployment

This chart is the Kubernetes deployment baseline for Identrail.

## Location

- Chart: `deploy/helm/identrail`

## Quick Start

1. Copy default values:
   - `cp deploy/helm/identrail/values.yaml /tmp/identrail-values.yaml`
2. Set production secrets in `/tmp/identrail-values.yaml` under `secret.data`.
3. Install or upgrade:
   - `helm upgrade --install identrail deploy/helm/identrail -n identrail --create-namespace -f /tmp/identrail-values.yaml`
4. Verify:
   - `kubectl -n identrail get pods`
   - `kubectl -n identrail get svc`

## Notes

- For production, prefer `secret.existingSecret` and set `secret.create=false`.
- Enable web deployment by setting `web.enabled=true`.
- Enable ingress by setting `ingress.enabled=true`.
- `IDENTRAIL_AUDIT_LOG_FILE` is empty by default. If you enable it, mount a writable path for the container user.
