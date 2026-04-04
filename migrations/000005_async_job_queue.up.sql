ALTER TABLE repo_scans
    ADD COLUMN IF NOT EXISTS history_limit INTEGER NOT NULL DEFAULT 0;

ALTER TABLE repo_scans
    ADD COLUMN IF NOT EXISTS max_findings_limit INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_scans_provider_status_started_at
    ON scans (provider, status, started_at ASC);

CREATE INDEX IF NOT EXISTS idx_scans_status_started_at
    ON scans (status, started_at ASC);

CREATE INDEX IF NOT EXISTS idx_repo_scans_status_started_at
    ON repo_scans (status, started_at ASC);

CREATE INDEX IF NOT EXISTS idx_repo_scans_repository_status_started_at
    ON repo_scans (repository, status, started_at ASC);
