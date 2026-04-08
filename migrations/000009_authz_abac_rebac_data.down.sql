DROP POLICY IF EXISTS authz_relationships_scope_isolation ON authz_relationships;
ALTER TABLE authz_relationships NO FORCE ROW LEVEL SECURITY;
ALTER TABLE authz_relationships DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS authz_entity_attributes_scope_isolation ON authz_entity_attributes;
ALTER TABLE authz_entity_attributes NO FORCE ROW LEVEL SECURITY;
ALTER TABLE authz_entity_attributes DISABLE ROW LEVEL SECURITY;

DROP TABLE IF EXISTS authz_relationships;
DROP TABLE IF EXISTS authz_entity_attributes;
