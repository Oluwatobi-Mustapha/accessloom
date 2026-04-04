ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';

ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS workspace_id TEXT NOT NULL DEFAULT 'default';

ALTER TABLE repo_scans
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';

ALTER TABLE repo_scans
    ADD COLUMN IF NOT EXISTS workspace_id TEXT NOT NULL DEFAULT 'default';

UPDATE scans
SET tenant_id = 'default'
WHERE COALESCE(TRIM(tenant_id), '') = '';

UPDATE scans
SET workspace_id = 'default'
WHERE COALESCE(TRIM(workspace_id), '') = '';

UPDATE repo_scans
SET tenant_id = 'default'
WHERE COALESCE(TRIM(tenant_id), '') = '';

UPDATE repo_scans
SET workspace_id = 'default'
WHERE COALESCE(TRIM(workspace_id), '') = '';

CREATE INDEX IF NOT EXISTS idx_scans_scope_started_at
    ON scans (tenant_id, workspace_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_scans_scope_provider_status_started_at
    ON scans (tenant_id, workspace_id, provider, status, started_at ASC);

CREATE INDEX IF NOT EXISTS idx_repo_scans_scope_started_at
    ON repo_scans (tenant_id, workspace_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_repo_scans_scope_status_started_at
    ON repo_scans (tenant_id, workspace_id, status, started_at ASC);

CREATE INDEX IF NOT EXISTS idx_repo_scans_scope_repository_status_started_at
    ON repo_scans (tenant_id, workspace_id, repository, status, started_at ASC);
