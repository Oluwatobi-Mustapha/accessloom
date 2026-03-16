CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY,
    provider TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    asset_count INTEGER NOT NULL DEFAULT 0,
    finding_count INTEGER NOT NULL DEFAULT 0,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans (started_at DESC);

CREATE TABLE IF NOT EXISTS raw_assets (
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    source_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload JSONB NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (scan_id, source_id, kind)
);

CREATE TABLE IF NOT EXISTS identities (
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    provider TEXT NOT NULL,
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    arn TEXT,
    owner_hint TEXT,
    created_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    tags JSONB,
    raw_ref TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (scan_id, id)
);

CREATE INDEX IF NOT EXISTS idx_identities_scan_id ON identities (scan_id);
CREATE INDEX IF NOT EXISTS idx_identities_provider_type ON identities (provider, type);

CREATE TABLE IF NOT EXISTS policies (
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    provider TEXT NOT NULL,
    name TEXT NOT NULL,
    document TEXT,
    normalized JSONB,
    raw_ref TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (scan_id, id)
);

CREATE INDEX IF NOT EXISTS idx_policies_scan_id ON policies (scan_id);

CREATE TABLE IF NOT EXISTS relationships (
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    type TEXT NOT NULL,
    from_node_id TEXT NOT NULL,
    to_node_id TEXT NOT NULL,
    evidence_ref TEXT,
    discovered_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (scan_id, id)
);

CREATE INDEX IF NOT EXISTS idx_relationships_scan_id ON relationships (scan_id);
CREATE INDEX IF NOT EXISTS idx_relationships_from_to ON relationships (from_node_id, to_node_id);

CREATE TABLE IF NOT EXISTS permissions (
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    identity_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    effect TEXT NOT NULL,
    PRIMARY KEY (scan_id, identity_id, action, resource, effect)
);

CREATE TABLE IF NOT EXISTS findings (
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    human_summary TEXT NOT NULL,
    path JSONB,
    evidence JSONB,
    remediation TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (scan_id, finding_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity);

CREATE TABLE IF NOT EXISTS ownership_signals (
    id TEXT PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    identity_id TEXT NOT NULL,
    team TEXT,
    repository TEXT,
    source TEXT,
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_ownership_signals_identity_id ON ownership_signals (identity_id);
