DROP POLICY IF EXISTS rbac_bindings_scope_isolation ON rbac_bindings;
ALTER TABLE rbac_bindings NO FORCE ROW LEVEL SECURITY;
ALTER TABLE rbac_bindings DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rbac_role_permissions_scope_isolation ON rbac_role_permissions;
ALTER TABLE rbac_role_permissions NO FORCE ROW LEVEL SECURITY;
ALTER TABLE rbac_role_permissions DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rbac_roles_scope_isolation ON rbac_roles;
ALTER TABLE rbac_roles NO FORCE ROW LEVEL SECURITY;
ALTER TABLE rbac_roles DISABLE ROW LEVEL SECURITY;

DROP INDEX IF EXISTS idx_rbac_bindings_scope_subject;
DROP INDEX IF EXISTS idx_rbac_bindings_scope_subject_role;
DROP INDEX IF EXISTS idx_rbac_roles_scope_name;

DROP TABLE IF EXISTS rbac_bindings;
DROP TABLE IF EXISTS rbac_role_permissions;
DROP TABLE IF EXISTS rbac_roles;
