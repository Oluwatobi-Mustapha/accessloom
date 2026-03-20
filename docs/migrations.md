# Migration Strategy

Simple migration strategy for production safety.

## Principles

- Use versioned SQL files in `migrations/`.
- Keep `*.up.sql` forward-safe and idempotent (`IF NOT EXISTS` where possible).
- Keep matching `*.down.sql` for controlled rollback.
- Treat rollback as an operator action, not an automatic startup action.

## Runtime Behavior

- API startup can auto-apply up migrations when:
  - `IDENTRAIL_RUN_MIGRATIONS=true`
  - `IDENTRAIL_MIGRATIONS_DIR` points to the migration folder.
- Down migrations are intentionally manual.

## Roll Forward (Preferred)

1. Deploy new app version with `IDENTRAIL_RUN_MIGRATIONS=true`.
2. Verify `/healthz` and one scan smoke run.
3. Keep worker disabled until API checks pass, then enable worker.

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
