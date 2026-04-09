ALTER TABLE authz_policy_rollouts
    DROP CONSTRAINT IF EXISTS authz_policy_rollouts_validated_versions_array,
    DROP CONSTRAINT IF EXISTS authz_policy_rollouts_workspace_allowlist_array,
    DROP CONSTRAINT IF EXISTS authz_policy_rollouts_tenant_allowlist_array,
    DROP CONSTRAINT IF EXISTS authz_policy_rollouts_canary_percentage_valid;

ALTER TABLE authz_policy_rollouts
    DROP COLUMN IF EXISTS validated_versions,
    DROP COLUMN IF EXISTS canary_percentage,
    DROP COLUMN IF EXISTS workspace_allowlist,
    DROP COLUMN IF EXISTS tenant_allowlist;
