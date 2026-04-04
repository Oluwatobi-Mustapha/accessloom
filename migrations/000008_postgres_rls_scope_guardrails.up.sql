CREATE OR REPLACE FUNCTION identrail_rls_scope_matches(row_tenant TEXT, row_workspace TEXT)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $$
    SELECT
        COALESCE(current_setting('identrail.rls_enforce', true), 'off') <> 'on'
        OR (
            NULLIF(current_setting('identrail.tenant_id', true), '') IS NOT NULL
            AND NULLIF(current_setting('identrail.workspace_id', true), '') IS NOT NULL
            AND row_tenant = current_setting('identrail.tenant_id', true)
            AND row_workspace = current_setting('identrail.workspace_id', true)
        );
$$;

CREATE OR REPLACE FUNCTION identrail_rls_scan_scope_matches(scan_uuid UUID)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM scans s
        WHERE s.id = scan_uuid
          AND identrail_rls_scope_matches(s.tenant_id, s.workspace_id)
    );
$$;

CREATE OR REPLACE FUNCTION identrail_rls_repo_scan_scope_matches(repo_scan_uuid UUID)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM repo_scans rs
        WHERE rs.id = repo_scan_uuid
          AND identrail_rls_scope_matches(rs.tenant_id, rs.workspace_id)
    );
$$;

ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scans_scope_isolation ON scans;
CREATE POLICY scans_scope_isolation ON scans
USING (identrail_rls_scope_matches(tenant_id, workspace_id))
WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));

ALTER TABLE raw_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE raw_assets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS raw_assets_scope_isolation ON raw_assets;
CREATE POLICY raw_assets_scope_isolation ON raw_assets
USING (identrail_rls_scan_scope_matches(scan_id))
WITH CHECK (identrail_rls_scan_scope_matches(scan_id));

ALTER TABLE identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE identities FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS identities_scope_isolation ON identities;
CREATE POLICY identities_scope_isolation ON identities
USING (identrail_rls_scan_scope_matches(scan_id))
WITH CHECK (identrail_rls_scan_scope_matches(scan_id));

ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS policies_scope_isolation ON policies;
CREATE POLICY policies_scope_isolation ON policies
USING (identrail_rls_scan_scope_matches(scan_id))
WITH CHECK (identrail_rls_scan_scope_matches(scan_id));

ALTER TABLE relationships ENABLE ROW LEVEL SECURITY;
ALTER TABLE relationships FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS relationships_scope_isolation ON relationships;
CREATE POLICY relationships_scope_isolation ON relationships
USING (identrail_rls_scan_scope_matches(scan_id))
WITH CHECK (identrail_rls_scan_scope_matches(scan_id));

ALTER TABLE permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE permissions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS permissions_scope_isolation ON permissions;
CREATE POLICY permissions_scope_isolation ON permissions
USING (identrail_rls_scan_scope_matches(scan_id))
WITH CHECK (identrail_rls_scan_scope_matches(scan_id));

ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS findings_scope_isolation ON findings;
CREATE POLICY findings_scope_isolation ON findings
USING (identrail_rls_scan_scope_matches(scan_id))
WITH CHECK (identrail_rls_scan_scope_matches(scan_id));

ALTER TABLE scan_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scan_events_scope_isolation ON scan_events;
CREATE POLICY scan_events_scope_isolation ON scan_events
USING (identrail_rls_scan_scope_matches(scan_id))
WITH CHECK (identrail_rls_scan_scope_matches(scan_id));

ALTER TABLE ownership_signals ENABLE ROW LEVEL SECURITY;
ALTER TABLE ownership_signals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ownership_signals_scope_isolation ON ownership_signals;
CREATE POLICY ownership_signals_scope_isolation ON ownership_signals
USING (identrail_rls_scan_scope_matches(scan_id))
WITH CHECK (identrail_rls_scan_scope_matches(scan_id));

ALTER TABLE repo_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE repo_scans FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS repo_scans_scope_isolation ON repo_scans;
CREATE POLICY repo_scans_scope_isolation ON repo_scans
USING (identrail_rls_scope_matches(tenant_id, workspace_id))
WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));

ALTER TABLE repo_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE repo_findings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS repo_findings_scope_isolation ON repo_findings;
CREATE POLICY repo_findings_scope_isolation ON repo_findings
USING (identrail_rls_repo_scan_scope_matches(repo_scan_id))
WITH CHECK (identrail_rls_repo_scan_scope_matches(repo_scan_id));

ALTER TABLE finding_triage_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_triage_states FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS finding_triage_states_scope_isolation ON finding_triage_states;
CREATE POLICY finding_triage_states_scope_isolation ON finding_triage_states
USING (identrail_rls_scope_matches(tenant_id, workspace_id))
WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));

ALTER TABLE finding_triage_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_triage_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS finding_triage_events_scope_isolation ON finding_triage_events;
CREATE POLICY finding_triage_events_scope_isolation ON finding_triage_events
USING (identrail_rls_scope_matches(tenant_id, workspace_id))
WITH CHECK (identrail_rls_scope_matches(tenant_id, workspace_id));
