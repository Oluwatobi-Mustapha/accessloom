# Enterprise 5-Minute Quickstart

This quickstart gets Identrail running with enterprise-safe defaults for auth scope, tenant/workspace context, and decision audit logging.

## Prerequisites

- Docker + Docker Compose
- `curl` + `jq`

## 1. Configure Environment

```bash
cp deploy/docker/.env.example deploy/docker/.env
```

Edit `deploy/docker/.env` and set at minimum:

- `IDENTRAIL_API_KEYS` with strong unique keys
- `IDENTRAIL_WRITE_API_KEYS` with write-capable keys
- `IDENTRAIL_POSTGRES_PASSWORD` with a strong database password
- `IDENTRAIL_API_KEY_SCOPES` (required for this quickstart), for example:
  - `IDENTRAIL_API_KEY_SCOPES=<reader-key>:read;<writer-key>:read,write;<admin-key>:read,write,admin`
- `IDENTRAIL_AUDIT_LOG_FILE=/tmp/identrail-audit.jsonl`

Optional hardening:
- `IDENTRAIL_AUDIT_FORWARD_URL=https://audit.example.com/events`
- `IDENTRAIL_AUDIT_FORWARD_HMAC_SECRET=<strong-secret>`

## 2. Start the Stack

```bash
docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env up -d --build
```

## 3. Export Command Variables

Use the exact keys configured in `deploy/docker/.env`:

```bash
export IDENTRAIL_API_URL="http://localhost:8080"
export IDENTRAIL_TENANT_ID="tenant-a"
export IDENTRAIL_WORKSPACE_ID="workspace-a"
export IDENTRAIL_READER_KEY="<reader-key-from-.env>"
export IDENTRAIL_WRITER_KEY="<writer-key-from-.env>"
export IDENTRAIL_ADMIN_KEY="<admin-key-from-.env>"
```

If you are using the web dashboard, enter these same values in the top control bar:
- `API Key`
- `Tenant ID`
- `Workspace ID`

## 4. Health and Auth Smoke Checks

```bash
curl -sS "${IDENTRAIL_API_URL}/healthz"
```

```bash
curl -sS "${IDENTRAIL_API_URL}/v1/scans?limit=5" \
  -H "X-API-Key: ${IDENTRAIL_READER_KEY}" \
  -H "X-Identrail-Tenant-ID: ${IDENTRAIL_TENANT_ID}" \
  -H "X-Identrail-Workspace-ID: ${IDENTRAIL_WORKSPACE_ID}" | jq .
```

## 5. Trigger and Verify a Scan

```bash
SCAN_ID=$(
  curl -sS -X POST "${IDENTRAIL_API_URL}/v1/scans" \
    -H "X-API-Key: ${IDENTRAIL_WRITER_KEY}" \
    -H "X-Identrail-Tenant-ID: ${IDENTRAIL_TENANT_ID}" \
    -H "X-Identrail-Workspace-ID: ${IDENTRAIL_WORKSPACE_ID}" \
  | jq -r '.scan.id'
)
echo "scan_id=${SCAN_ID}"
```

```bash
curl -sS "${IDENTRAIL_API_URL}/v1/scans/${SCAN_ID}/events?limit=10" \
  -H "X-API-Key: ${IDENTRAIL_READER_KEY}" \
  -H "X-Identrail-Tenant-ID: ${IDENTRAIL_TENANT_ID}" \
  -H "X-Identrail-Workspace-ID: ${IDENTRAIL_WORKSPACE_ID}" | jq .
```

## 6. Verify AuthZ Decision Explainability

`/v1/authz/policies/simulate` requires an API key mapped to `admin` scope.

```bash
curl -sS -X POST "${IDENTRAIL_API_URL}/v1/authz/policies/simulate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${IDENTRAIL_ADMIN_KEY}" \
  -H "X-Identrail-Tenant-ID: ${IDENTRAIL_TENANT_ID}" \
  -H "X-Identrail-Workspace-ID: ${IDENTRAIL_WORKSPACE_ID}" \
  -d '{
    "subject": {"type":"subject","id":"user-1","roles":["admin"]},
    "action": "findings.read",
    "resource": {"type":"finding","id":"finding-1"},
    "context": {"request_path":"/v1/findings","request_method":"GET"}
  }' | jq '{decision, trace}'
```

Expected:
- `decision` contains `allowed`, `stage`, `reason`
- `trace` includes ordered stages from tenant isolation through default deny

## 7. Verify Decision Audit Log

```bash
docker exec identrail-api sh -lc 'tail -n 50 /tmp/identrail-audit.jsonl' \
  | jq -c 'select(.authz != null) | {method,path,status,authz}'
```

Confirm:
- authz decision block exists for protected routes
- no raw API key values in audit payload
- subject/resource IDs appear only as hashed identifiers (`*_id_hash`)

## 8. Clean Shutdown

```bash
docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env down
```
