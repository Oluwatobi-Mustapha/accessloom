CREATE TABLE IF NOT EXISTS authz_policy_sets (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    policy_set_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, workspace_id, policy_set_id)
);

CREATE TABLE IF NOT EXISTS authz_policy_versions (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    policy_set_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    bundle JSONB NOT NULL,
    checksum TEXT NOT NULL,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, workspace_id, policy_set_id, version),
    CONSTRAINT authz_policy_versions_set_fk
        FOREIGN KEY (tenant_id, workspace_id, policy_set_id)
        REFERENCES authz_policy_sets (tenant_id, workspace_id, policy_set_id)
        ON DELETE CASCADE,
    CONSTRAINT authz_policy_versions_version_positive CHECK (version > 0)
);

CREATE TABLE IF NOT EXISTS authz_policy_rollouts (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    policy_set_id TEXT NOT NULL,
    active_version INTEGER,
    candidate_version INTEGER,
    mode TEXT NOT NULL,
    updated_by TEXT,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, workspace_id, policy_set_id),
    CONSTRAINT authz_policy_rollouts_set_fk
        FOREIGN KEY (tenant_id, workspace_id, policy_set_id)
        REFERENCES authz_policy_sets (tenant_id, workspace_id, policy_set_id)
        ON DELETE CASCADE,
    CONSTRAINT authz_policy_rollouts_active_version_fk
        FOREIGN KEY (tenant_id, workspace_id, policy_set_id, active_version)
        REFERENCES authz_policy_versions (tenant_id, workspace_id, policy_set_id, version),
    CONSTRAINT authz_policy_rollouts_candidate_version_fk
        FOREIGN KEY (tenant_id, workspace_id, policy_set_id, candidate_version)
        REFERENCES authz_policy_versions (tenant_id, workspace_id, policy_set_id, version),
    CONSTRAINT authz_policy_rollouts_mode_valid CHECK (mode IN ('disabled', 'shadow', 'enforce')),
    CONSTRAINT authz_policy_rollouts_active_version_positive CHECK (active_version IS NULL OR active_version > 0),
    CONSTRAINT authz_policy_rollouts_candidate_version_positive CHECK (candidate_version IS NULL OR candidate_version > 0)
);

CREATE TABLE IF NOT EXISTS authz_policy_events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    policy_set_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    from_version INTEGER,
    to_version INTEGER,
    actor TEXT,
    message TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT authz_policy_events_set_fk
        FOREIGN KEY (tenant_id, workspace_id, policy_set_id)
        REFERENCES authz_policy_sets (tenant_id, workspace_id, policy_set_id)
        ON DELETE CASCADE,
    CONSTRAINT authz_policy_events_from_version_positive CHECK (from_version IS NULL OR from_version > 0),
    CONSTRAINT authz_policy_events_to_version_positive CHECK (to_version IS NULL OR to_version > 0)
);

CREATE INDEX IF NOT EXISTS idx_authz_policy_versions_scope_set_created
    ON authz_policy_versions (tenant_id, workspace_id, policy_set_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_authz_policy_rollouts_scope_mode
    ON authz_policy_rollouts (tenant_id, workspace_id, mode);
CREATE INDEX IF NOT EXISTS idx_authz_policy_events_scope_set_created
    ON authz_policy_events (tenant_id, workspace_id, policy_set_id, created_at DESC);

ALTER TABLE authz_policy_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE authz_policy_sets FORCE ROW LEVEL SECURITY;
ALTER TABLE authz_policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE authz_policy_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE authz_policy_rollouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE authz_policy_rollouts FORCE ROW LEVEL SECURITY;
ALTER TABLE authz_policy_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE authz_policy_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS authz_policy_sets_scope_isolation ON authz_policy_sets;
CREATE POLICY authz_policy_sets_scope_isolation ON authz_policy_sets
    USING (identrail_rls_scope_matches(tenant_id, workspace_id))
    WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));

DROP POLICY IF EXISTS authz_policy_versions_scope_isolation ON authz_policy_versions;
CREATE POLICY authz_policy_versions_scope_isolation ON authz_policy_versions
    USING (identrail_rls_scope_matches(tenant_id, workspace_id))
    WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));

DROP POLICY IF EXISTS authz_policy_rollouts_scope_isolation ON authz_policy_rollouts;
CREATE POLICY authz_policy_rollouts_scope_isolation ON authz_policy_rollouts
    USING (identrail_rls_scope_matches(tenant_id, workspace_id))
    WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));

DROP POLICY IF EXISTS authz_policy_events_scope_isolation ON authz_policy_events;
CREATE POLICY authz_policy_events_scope_isolation ON authz_policy_events
    USING (identrail_rls_scope_matches(tenant_id, workspace_id))
    WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));
