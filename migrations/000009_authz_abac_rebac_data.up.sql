CREATE TABLE IF NOT EXISTS authz_entity_attributes (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    entity_kind TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    owner_team TEXT,
    env TEXT,
    risk_tier TEXT,
    classification TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, workspace_id, entity_kind, entity_type, entity_id),
    CHECK (entity_kind IN ('subject', 'resource')),
    CHECK (env IS NULL OR env IN ('prod', 'staging', 'dev', 'test', 'sandbox')),
    CHECK (risk_tier IS NULL OR risk_tier IN ('low', 'medium', 'high', 'critical')),
    CHECK (classification IS NULL OR classification IN ('public', 'internal', 'confidential', 'restricted'))
);

CREATE INDEX IF NOT EXISTS idx_authz_entity_attributes_scope_kind_type
    ON authz_entity_attributes (tenant_id, workspace_id, entity_kind, entity_type);

CREATE TABLE IF NOT EXISTS authz_relationships (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'manual',
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, workspace_id, subject_type, subject_id, relation, object_type, object_id),
    CHECK (relation IN ('owns', 'manages', 'delegated_admin', 'member_of'))
);

CREATE INDEX IF NOT EXISTS idx_authz_relationships_scope_subject_relation
    ON authz_relationships (tenant_id, workspace_id, subject_type, subject_id, relation);

CREATE INDEX IF NOT EXISTS idx_authz_relationships_scope_object_relation
    ON authz_relationships (tenant_id, workspace_id, object_type, object_id, relation);

CREATE INDEX IF NOT EXISTS idx_authz_relationships_scope_expires_at
    ON authz_relationships (tenant_id, workspace_id, expires_at);

ALTER TABLE authz_entity_attributes ENABLE ROW LEVEL SECURITY;
ALTER TABLE authz_entity_attributes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS authz_entity_attributes_scope_isolation ON authz_entity_attributes;
CREATE POLICY authz_entity_attributes_scope_isolation ON authz_entity_attributes
USING (identrail_rls_scope_matches(tenant_id, workspace_id))
WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));

ALTER TABLE authz_relationships ENABLE ROW LEVEL SECURITY;
ALTER TABLE authz_relationships FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS authz_relationships_scope_isolation ON authz_relationships;
CREATE POLICY authz_relationships_scope_isolation ON authz_relationships
USING (identrail_rls_scope_matches(tenant_id, workspace_id))
WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));
