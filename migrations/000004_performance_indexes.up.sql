CREATE INDEX IF NOT EXISTS idx_findings_scan_severity_type_created
    ON findings (scan_id, severity, type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_findings_created_at
    ON findings (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_repo_findings_scan_severity_type_created
    ON repo_findings (repo_scan_id, severity, type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_repo_findings_created_at
    ON repo_findings (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_scan_events_scan_level_created
    ON scan_events (scan_id, level, created_at DESC);
