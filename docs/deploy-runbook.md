# Deploy Runbook

Simple operational runbook for Identrail API/worker deploys.

Portable deployment profiles:
- Docker: `deploy/docker/`
- Kubernetes: `deploy/kubernetes/`
- Linux VM/systemd: `deploy/systemd/`
- Guide: `docs/deployment-anywhere.md`
- Operator readiness: `docs/operator-readiness.md`
- Troubleshooting playbook: `docs/troubleshooting.md`
- Incident workflow: `docs/incident-response.md`
- Security baseline: `docs/security-hardening.md`
- Observability baseline: `docs/observability.md`
- API contract: `docs/openapi-v1.yaml`
- Migration policy: `docs/migrations.md`
- V1 release qualification: `docs/v1_release_qualification.md`

## 1) Pre-Deploy Checklist

- Confirm `IDENTRAIL_DATABASE_URL` points to target environment.
- Confirm migrations path is correct (`IDENTRAIL_MIGRATIONS_DIR`).
- Confirm shared API/worker config keeps `IDENTRAIL_RUN_MIGRATIONS=false`.
- Confirm lock backend for deployment shape:
  - single instance: `IDENTRAIL_LOCK_BACKEND=inmemory` or `auto`
  - multi-instance: `IDENTRAIL_LOCK_BACKEND=postgres`
  - set `IDENTRAIL_LOCK_NAMESPACE` to isolate lock domains between environments
- Confirm API auth is configured:
  - legacy: `IDENTRAIL_API_KEYS` (+ `IDENTRAIL_WRITE_API_KEYS`)
  - scoped: `IDENTRAIL_API_KEY_SCOPES`
- Confirm alert config:
  - `IDENTRAIL_ALERT_WEBHOOK_URL`
  - `IDENTRAIL_ALERT_MIN_SEVERITY`
  - optional `IDENTRAIL_ALERT_HMAC_SECRET`
  - `IDENTRAIL_ALERT_MAX_RETRIES`
  - `IDENTRAIL_ALERT_RETRY_BACKOFF`
- Confirm audit forwarding config (if enabled):
  - `IDENTRAIL_AUDIT_FORWARD_URL`
  - `IDENTRAIL_AUDIT_FORWARD_TIMEOUT`
  - `IDENTRAIL_AUDIT_FORWARD_MAX_RETRIES`
  - `IDENTRAIL_AUDIT_FORWARD_RETRY_BACKOFF`
  - optional `IDENTRAIL_AUDIT_FORWARD_HMAC_SECRET`
- If worker repo scans are enabled, confirm:
  - `IDENTRAIL_WORKER_REPO_SCAN_ENABLED=true`
  - `IDENTRAIL_WORKER_REPO_SCAN_TARGETS` has intended repositories
  - targets are covered by `IDENTRAIL_REPO_SCAN_ALLOWLIST` when allowlist is set
- Confirm API queue controls:
  - `IDENTRAIL_SCAN_QUEUE_MAX_PENDING`
  - `IDENTRAIL_REPO_SCAN_QUEUE_MAX_PENDING`
  - `IDENTRAIL_WORKER_API_JOB_QUEUE_ENABLED=true`
  - `IDENTRAIL_WORKER_API_JOB_QUEUE_INTERVAL`
  - `IDENTRAIL_WORKER_API_JOB_QUEUE_BATCH_SIZE`

## 2) Deploy Sequence

1. Ensure CI is green on `main` (`Go Quality`, `Go Tests`, `Go Integration (Postgres)`, `Web Build`).
2. Run migrations once using the dedicated migration job:
   - Kubernetes manifests: apply `deploy/kubernetes/migration-job.yaml` and wait for job completion.
   - Helm: pre-install/pre-upgrade hook job runs automatically when `migrations.enabled=true`.
3. Deploy API service with `IDENTRAIL_RUN_MIGRATIONS=false`.
4. Verify health endpoint: `GET /healthz`.
5. Deploy worker with same DB + provider config (`IDENTRAIL_RUN_MIGRATIONS=false`).
6. Trigger one scan (`POST /v1/scans`) with write-authorized key.
7. Verify:
  - scan is accepted as queued (`202`) then completed by worker
  - findings list (`GET /v1/findings`)
  - findings summary (`GET /v1/findings/summary`)
  - findings trends (`GET /v1/findings/trends`)
  - scan diff (`GET /v1/scans/:scan_id/diff`)
  - scan events (`GET /v1/scans/:scan_id/events`)
8. If repo scan is enabled:
   - trigger `POST /v1/repo-scans`
   - verify `GET /v1/repo-scans`
   - verify `GET /v1/repo-findings?repo_scan_id=<id>`

## 3) Rollback Sequence

1. Stop worker to avoid new writes during rollback.
2. Roll back API to previous image.
3. If schema rollback is required, apply matching down migration manually.
4. Re-run health checks and one scan smoke test.

## 4) Key Rotation

1. Add new keys/scoped keys to environment.
2. Deploy services.
3. Validate new key access.
4. Remove old keys.
5. Deploy again.

## 5) Alert Webhook Verification

1. Trigger a scan that emits `high` or `critical` finding.
2. Confirm webhook receiver gets payload.
3. Confirm `X-Identrail-Signature` validation if secret is configured.
4. If receiver is temporarily failing, confirm retries are visible in receiver logs.

## 6) Incident Clues

- For API activity trace: check audit log sink (`IDENTRAIL_AUDIT_LOG_FILE`).
- For scan lifecycle: check `/v1/scans/:scan_id/events`.
- For alert delivery issues: check API/worker warning logs for alert delivery failures.
