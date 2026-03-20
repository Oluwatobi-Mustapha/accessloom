# Helm Deployment

This chart is the Kubernetes deployment baseline for Identrail.

## Location

- Chart: `deploy/helm/identrail`

## Quick Start

1. Copy default values:
   - `cp deploy/helm/identrail/values.yaml /tmp/identrail-values.yaml`
2. Create the runtime secret referenced by default (`identrail-secrets`):
   - `kubectl -n identrail create secret generic identrail-secrets --from-literal=IDENTRAIL_API_KEYS='READ_KEY,WRITE_KEY' --from-literal=IDENTRAIL_WRITE_API_KEYS='WRITE_KEY' --from-literal=IDENTRAIL_DATABASE_URL='postgres://identrail:password@postgres:5432/identrail?sslmode=require'`
3. (Optional) If you want Helm to create the secret instead, set `secret.create=true` and provide `secret.data`.
4. Install or upgrade:
   - `helm upgrade --install identrail deploy/helm/identrail -n identrail --create-namespace -f /tmp/identrail-values.yaml`
5. Verify:
   - `kubectl -n identrail get pods`
   - `kubectl -n identrail get svc`

## Notes

- Default mode uses `secret.existingSecret=identrail-secrets` with `secret.create=false`.
- Enable web deployment by setting `web.enabled=true`.
- Enable ingress by setting `ingress.enabled=true`.
- `IDENTRAIL_AUDIT_LOG_FILE` is empty by default. If you enable it, mount a writable path for the container user.
