# Migration Strategy

Simple migration strategy for production safety.

## Principles

- Use versioned SQL files in `migrations/`.
- Keep `*.up.sql` forward-safe and idempotent (`IF NOT EXISTS` where possible).
- Keep matching `*.down.sql` for controlled rollback.
- Treat rollback as an operator action, not an automatic startup action.

## Runtime Behavior

- Shared API/worker deployments must run with `IDENTRAIL_RUN_MIGRATIONS=false`.
- Run schema migrations in a single one-shot migrator process:
  - Kubernetes manifests: `deploy/kubernetes/migration-job.yaml`
  - Helm chart: pre-install/pre-upgrade migration Job hook
- The migrator job sets:
  - `IDENTRAIL_RUN_MIGRATIONS=true`
  - `IDENTRAIL_RUN_MIGRATIONS_ONLY=true`
- Down migrations are intentionally manual.

## Roll Forward (Preferred)

1. Deploy and wait for the dedicated migrator job to complete successfully.
2. Deploy API and worker pods with `IDENTRAIL_RUN_MIGRATIONS=false`.
3. Verify `/healthz` and one scan smoke run.

## Rollback Procedure

1. Stop worker first to prevent new writes.
2. Roll back API image to previous known-good version.
3. Apply the specific down migration(s) only if schema rollback is required.
4. Re-apply previous up migration set if needed.
5. Re-run smoke checks (`/healthz`, one scan trigger, findings list).

## Verification

- CI integration lane now includes migration roundtrip verification:
  - apply up -> apply down -> apply up
  - run scan and verify persistence still works.
