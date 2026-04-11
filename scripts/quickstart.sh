#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_EXAMPLE="${ROOT_DIR}/deploy/docker/.env.example"
ENV_FILE="${ROOT_DIR}/deploy/docker/.env"
COMPOSE_FILE="${ROOT_DIR}/deploy/docker/docker-compose.yml"
API_URL="${IDENTRAIL_API_URL:-http://localhost:8080}"
WEB_URL="${IDENTRAIL_WEB_URL:-http://localhost:8081}"
HEALTH_URL="${API_URL}/healthz"
SCAN_URL="${API_URL}/v1/scans"
FINDINGS_URL="${API_URL}/v1/findings?limit=5"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker is required"
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required"
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "ERROR: openssl is required"
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: docker compose plugin is required"
  exit 1
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  cp "${ENV_EXAMPLE}" "${ENV_FILE}"
  echo "Created ${ENV_FILE} from template."
fi

upsert_env() {
  local key="$1"
  local value="$2"
  local tmp_file
  tmp_file="$(mktemp)"
  awk -v key="${key}" -v value="${value}" '
    BEGIN { replaced = 0 }
    $0 ~ ("^" key "=") {
      if (!replaced) {
        print key "=" value
        replaced = 1
      }
      next
    }
    { print }
    END {
      if (!replaced) {
        print key "=" value
      }
    }
  ' "${ENV_FILE}" >"${tmp_file}"
  mv "${tmp_file}" "${ENV_FILE}"
}

READ_KEY="$(openssl rand -hex 24)"
WRITE_KEY="$(openssl rand -hex 24)"
DB_PASSWORD="$(openssl rand -hex 24)"

upsert_env "IDENTRAIL_API_KEYS" "${READ_KEY},${WRITE_KEY}"
upsert_env "IDENTRAIL_WRITE_API_KEYS" "${WRITE_KEY}"
upsert_env "IDENTRAIL_POSTGRES_PASSWORD" "${DB_PASSWORD}"
upsert_env "IDENTRAIL_WORKER_RUN_NOW" "false"

docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" up -d --build

echo "Waiting for API health endpoint..."
healthy="false"
for _ in $(seq 1 45); do
  if curl -fsS "${HEALTH_URL}" >/dev/null; then
    healthy="true"
    break
  fi
  sleep 2
done

if [[ "${healthy}" != "true" ]]; then
  echo "ERROR: API did not become healthy."
  docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" ps
  docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" logs api postgres || true
  exit 1
fi

SCAN_JSON="$(
  curl -fsS -X POST "${SCAN_URL}" \
    -H "X-API-Key: ${WRITE_KEY}" \
    -H "Content-Type: application/json"
)"
SCAN_ID="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["scan"]["id"])' <<<"${SCAN_JSON}")"

echo "Triggered first scan: ${SCAN_ID}"

for _ in $(seq 1 45); do
  FINDINGS_JSON="$(curl -fsS "${FINDINGS_URL}" -H "X-API-Key: ${READ_KEY}")"
  FINDING_COUNT="$(python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("items", [])))' <<<"${FINDINGS_JSON}")"
  if [[ "${FINDING_COUNT}" -gt 0 ]]; then
    break
  fi
  sleep 2
done

echo
echo "Quickstart completed."
echo "API: ${API_URL}"
echo "Web: ${WEB_URL}"
echo "Scan ID: ${SCAN_ID}"
echo
echo "Read findings:"
echo "curl -sS \"${FINDINGS_URL}\" -H \"X-API-Key: ${READ_KEY}\" | python3 -m json.tool"
echo
echo "When done:"
echo "docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env down"
