DROP INDEX IF EXISTS idx_repo_scans_repository_status_started_at;
DROP INDEX IF EXISTS idx_repo_scans_status_started_at;
DROP INDEX IF EXISTS idx_scans_status_started_at;
DROP INDEX IF EXISTS idx_scans_provider_status_started_at;

ALTER TABLE repo_scans
    DROP COLUMN IF EXISTS max_findings_limit;

ALTER TABLE repo_scans
    DROP COLUMN IF EXISTS history_limit;
