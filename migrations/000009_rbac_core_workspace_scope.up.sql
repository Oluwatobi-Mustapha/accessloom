CREATE TABLE IF NOT EXISTS rbac_roles (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    is_builtin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_rbac_roles_scope_name
    ON rbac_roles (tenant_id, workspace_id, name);

CREATE TABLE IF NOT EXISTS rbac_role_permissions (
    role_id TEXT NOT NULL REFERENCES rbac_roles(id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (role_id, permission)
);

CREATE TABLE IF NOT EXISTS rbac_bindings (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    role_id TEXT NOT NULL REFERENCES rbac_roles(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_rbac_bindings_scope_subject_role
    ON rbac_bindings (tenant_id, workspace_id, subject_type, subject_id, role_id);

CREATE INDEX IF NOT EXISTS idx_rbac_bindings_scope_subject
    ON rbac_bindings (tenant_id, workspace_id, subject_type, subject_id, created_at DESC);

ALTER TABLE rbac_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE rbac_roles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rbac_roles_scope_isolation ON rbac_roles;
CREATE POLICY rbac_roles_scope_isolation ON rbac_roles
USING (identrail_rls_scope_matches(tenant_id, workspace_id))
WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));

ALTER TABLE rbac_role_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE rbac_role_permissions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rbac_role_permissions_scope_isolation ON rbac_role_permissions;
CREATE POLICY rbac_role_permissions_scope_isolation ON rbac_role_permissions
USING (
    EXISTS (
        SELECT 1
        FROM rbac_roles r
        WHERE r.id = rbac_role_permissions.role_id
          AND identrail_rls_scope_matches(r.tenant_id, r.workspace_id)
    )
)
WITH CHECK (
    EXISTS (
        SELECT 1
        FROM rbac_roles r
        WHERE r.id = rbac_role_permissions.role_id
          AND identrail_rls_scope_matches(r.tenant_id, r.workspace_id)
    )
);

ALTER TABLE rbac_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE rbac_bindings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rbac_bindings_scope_isolation ON rbac_bindings;
CREATE POLICY rbac_bindings_scope_isolation ON rbac_bindings
USING (identrail_rls_scope_matches(tenant_id, workspace_id))
WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));
