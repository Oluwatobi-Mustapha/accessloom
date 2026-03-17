CREATE TABLE IF NOT EXISTS repo_scans (
    id UUID PRIMARY KEY,
    repository TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    commits_scanned INTEGER NOT NULL DEFAULT 0,
    files_scanned INTEGER NOT NULL DEFAULT 0,
    finding_count INTEGER NOT NULL DEFAULT 0,
    truncated BOOLEAN NOT NULL DEFAULT FALSE,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_repo_scans_started_at ON repo_scans (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_repo_scans_repository ON repo_scans (repository);

CREATE TABLE IF NOT EXISTS repo_findings (
    repo_scan_id UUID NOT NULL REFERENCES repo_scans(id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    human_summary TEXT NOT NULL,
    path JSONB,
    evidence JSONB,
    remediation TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (repo_scan_id, finding_id)
);

CREATE INDEX IF NOT EXISTS idx_repo_findings_scan_id ON repo_findings (repo_scan_id);
CREATE INDEX IF NOT EXISTS idx_repo_findings_severity ON repo_findings (severity);
