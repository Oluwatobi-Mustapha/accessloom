DROP INDEX IF EXISTS idx_finding_triage_events_scope_finding_created;
DROP INDEX IF EXISTS idx_finding_triage_states_scope_assignee;
DROP INDEX IF EXISTS idx_finding_triage_states_scope_status;

CREATE INDEX IF NOT EXISTS idx_finding_triage_states_status
    ON finding_triage_states (status);

CREATE INDEX IF NOT EXISTS idx_finding_triage_states_assignee
    ON finding_triage_states (assignee);

CREATE INDEX IF NOT EXISTS idx_finding_triage_events_finding_created
    ON finding_triage_events (finding_id, created_at DESC);

DELETE FROM finding_triage_states a
USING finding_triage_states b
WHERE a.finding_id = b.finding_id
  AND (a.tenant_id, a.workspace_id) <> (b.tenant_id, b.workspace_id)
  AND a.ctid < b.ctid;

ALTER TABLE finding_triage_states
    DROP CONSTRAINT IF EXISTS finding_triage_states_pkey;

ALTER TABLE finding_triage_states
    ADD CONSTRAINT finding_triage_states_pkey PRIMARY KEY (finding_id);

ALTER TABLE finding_triage_events
    DROP COLUMN IF EXISTS workspace_id;

ALTER TABLE finding_triage_events
    DROP COLUMN IF EXISTS tenant_id;

ALTER TABLE finding_triage_states
    DROP COLUMN IF EXISTS workspace_id;

ALTER TABLE finding_triage_states
    DROP COLUMN IF EXISTS tenant_id;
