#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "[1/8] Go unit/package tests"
go test ./...

echo "[2/8] Integration tests (requires IDENTRAIL_INTEGRATION_DATABASE_URL)"
if [[ -n "${IDENTRAIL_INTEGRATION_DATABASE_URL:-}" ]]; then
  go test -tags=integration ./internal/integration -count=1 -v
else
  echo "ERROR: IDENTRAIL_INTEGRATION_DATABASE_URL is not set"
  exit 1
fi

echo "[3/8] Web tests/build"
if command -v npm >/dev/null 2>&1; then
  npm ci --prefix web
  npm run test:ci --prefix web
  npm run build --prefix web
else
  echo "ERROR: npm is required for release qualification"
  exit 1
fi

echo "[4/8] Docker compose config validation"
compose_env_path="deploy/docker/.env"
compose_env_backup=""
cleanup_compose_env() {
  if [[ -n "${compose_env_backup}" && -f "${compose_env_backup}" ]]; then
    mv "${compose_env_backup}" "${compose_env_path}"
    compose_env_backup=""
    return
  fi
  rm -f "${compose_env_path}"
}
if [[ -f "${compose_env_path}" ]]; then
  compose_env_backup="$(mktemp)"
  cp "${compose_env_path}" "${compose_env_backup}"
fi
trap cleanup_compose_env EXIT
cp deploy/docker/.env.example "${compose_env_path}"
docker compose -f deploy/docker/docker-compose.yml --env-file "${compose_env_path}" config >/tmp/identrail-compose.yml
cleanup_compose_env
trap - EXIT

echo "[5/8] Terraform validation"
if command -v terraform >/dev/null 2>&1; then
  terraform fmt -check -recursive deploy/terraform
  (
    cd deploy/terraform
    terraform init -backend=false
    terraform validate
  )
else
  echo "ERROR: terraform is required for release qualification"
  exit 1
fi

echo "[6/8] Helm lint"
if command -v helm >/dev/null 2>&1; then
  helm lint deploy/helm/identrail
else
  echo "ERROR: helm is required for release qualification"
  exit 1
fi

echo "[7/8] API SLO smoke tests"
go test ./internal/api -run TestFindingsListLatencySLOSmoke -count=1

echo "[8/8] Final status"
echo "V1 release qualification checks passed."
