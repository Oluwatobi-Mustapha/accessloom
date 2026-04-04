DROP POLICY IF EXISTS finding_triage_events_scope_isolation ON finding_triage_events;
ALTER TABLE finding_triage_events NO FORCE ROW LEVEL SECURITY;
ALTER TABLE finding_triage_events DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS finding_triage_states_scope_isolation ON finding_triage_states;
ALTER TABLE finding_triage_states NO FORCE ROW LEVEL SECURITY;
ALTER TABLE finding_triage_states DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS repo_findings_scope_isolation ON repo_findings;
ALTER TABLE repo_findings NO FORCE ROW LEVEL SECURITY;
ALTER TABLE repo_findings DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS repo_scans_scope_isolation ON repo_scans;
ALTER TABLE repo_scans NO FORCE ROW LEVEL SECURITY;
ALTER TABLE repo_scans DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS ownership_signals_scope_isolation ON ownership_signals;
ALTER TABLE ownership_signals NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ownership_signals DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS scan_events_scope_isolation ON scan_events;
ALTER TABLE scan_events NO FORCE ROW LEVEL SECURITY;
ALTER TABLE scan_events DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS findings_scope_isolation ON findings;
ALTER TABLE findings NO FORCE ROW LEVEL SECURITY;
ALTER TABLE findings DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS permissions_scope_isolation ON permissions;
ALTER TABLE permissions NO FORCE ROW LEVEL SECURITY;
ALTER TABLE permissions DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS relationships_scope_isolation ON relationships;
ALTER TABLE relationships NO FORCE ROW LEVEL SECURITY;
ALTER TABLE relationships DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS policies_scope_isolation ON policies;
ALTER TABLE policies NO FORCE ROW LEVEL SECURITY;
ALTER TABLE policies DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS identities_scope_isolation ON identities;
ALTER TABLE identities NO FORCE ROW LEVEL SECURITY;
ALTER TABLE identities DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS raw_assets_scope_isolation ON raw_assets;
ALTER TABLE raw_assets NO FORCE ROW LEVEL SECURITY;
ALTER TABLE raw_assets DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS scans_scope_isolation ON scans;
ALTER TABLE scans NO FORCE ROW LEVEL SECURITY;
ALTER TABLE scans DISABLE ROW LEVEL SECURITY;

DROP FUNCTION IF EXISTS identrail_rls_repo_scan_scope_matches(UUID);
DROP FUNCTION IF EXISTS identrail_rls_scan_scope_matches(UUID);
DROP FUNCTION IF EXISTS identrail_rls_scope_matches(TEXT, TEXT);
