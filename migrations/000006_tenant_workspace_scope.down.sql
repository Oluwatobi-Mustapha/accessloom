DROP INDEX IF EXISTS idx_repo_scans_scope_repository_status_started_at;
DROP INDEX IF EXISTS idx_repo_scans_scope_status_started_at;
DROP INDEX IF EXISTS idx_repo_scans_scope_started_at;
DROP INDEX IF EXISTS idx_scans_scope_provider_status_started_at;
DROP INDEX IF EXISTS idx_scans_scope_started_at;

ALTER TABLE repo_scans
    DROP COLUMN IF EXISTS workspace_id;

ALTER TABLE repo_scans
    DROP COLUMN IF EXISTS tenant_id;

ALTER TABLE scans
    DROP COLUMN IF EXISTS workspace_id;

ALTER TABLE scans
    DROP COLUMN IF EXISTS tenant_id;
