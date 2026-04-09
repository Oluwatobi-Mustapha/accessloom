DROP POLICY IF EXISTS authz_policy_events_scope_isolation ON authz_policy_events;
DROP POLICY IF EXISTS authz_policy_rollouts_scope_isolation ON authz_policy_rollouts;
DROP POLICY IF EXISTS authz_policy_versions_scope_isolation ON authz_policy_versions;
DROP POLICY IF EXISTS authz_policy_sets_scope_isolation ON authz_policy_sets;

DROP TABLE IF EXISTS authz_policy_events;
DROP TABLE IF EXISTS authz_policy_rollouts;
DROP TABLE IF EXISTS authz_policy_versions;
DROP TABLE IF EXISTS authz_policy_sets;
