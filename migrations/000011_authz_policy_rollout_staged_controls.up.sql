ALTER TABLE authz_policy_rollouts
    ADD COLUMN IF NOT EXISTS tenant_allowlist JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS workspace_allowlist JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS canary_percentage INTEGER NOT NULL DEFAULT 100,
    ADD COLUMN IF NOT EXISTS validated_versions JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE authz_policy_rollouts
    DROP CONSTRAINT IF EXISTS authz_policy_rollouts_canary_percentage_valid;
ALTER TABLE authz_policy_rollouts
    ADD CONSTRAINT authz_policy_rollouts_canary_percentage_valid CHECK (canary_percentage >= 0 AND canary_percentage <= 100);

ALTER TABLE authz_policy_rollouts
    DROP CONSTRAINT IF EXISTS authz_policy_rollouts_tenant_allowlist_array;
ALTER TABLE authz_policy_rollouts
    ADD CONSTRAINT authz_policy_rollouts_tenant_allowlist_array CHECK (jsonb_typeof(tenant_allowlist) = 'array');

ALTER TABLE authz_policy_rollouts
    DROP CONSTRAINT IF EXISTS authz_policy_rollouts_workspace_allowlist_array;
ALTER TABLE authz_policy_rollouts
    ADD CONSTRAINT authz_policy_rollouts_workspace_allowlist_array CHECK (jsonb_typeof(workspace_allowlist) = 'array');

ALTER TABLE authz_policy_rollouts
    DROP CONSTRAINT IF EXISTS authz_policy_rollouts_validated_versions_array;
ALTER TABLE authz_policy_rollouts
    ADD CONSTRAINT authz_policy_rollouts_validated_versions_array CHECK (jsonb_typeof(validated_versions) = 'array');
