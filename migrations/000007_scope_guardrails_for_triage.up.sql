ALTER TABLE finding_triage_states
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';

ALTER TABLE finding_triage_states
    ADD COLUMN IF NOT EXISTS workspace_id TEXT NOT NULL DEFAULT 'default';

ALTER TABLE finding_triage_events
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';

ALTER TABLE finding_triage_events
    ADD COLUMN IF NOT EXISTS workspace_id TEXT NOT NULL DEFAULT 'default';

UPDATE finding_triage_states
SET tenant_id = 'default'
WHERE COALESCE(TRIM(tenant_id), '') = '';

UPDATE finding_triage_states
SET workspace_id = 'default'
WHERE COALESCE(TRIM(workspace_id), '') = '';

UPDATE finding_triage_events
SET tenant_id = 'default'
WHERE COALESCE(TRIM(tenant_id), '') = '';

UPDATE finding_triage_events
SET workspace_id = 'default'
WHERE COALESCE(TRIM(workspace_id), '') = '';

ALTER TABLE finding_triage_states
    DROP CONSTRAINT IF EXISTS finding_triage_states_pkey;

ALTER TABLE finding_triage_states
    ADD CONSTRAINT finding_triage_states_pkey PRIMARY KEY (tenant_id, workspace_id, finding_id);

DROP INDEX IF EXISTS idx_finding_triage_states_status;
DROP INDEX IF EXISTS idx_finding_triage_states_assignee;
DROP INDEX IF EXISTS idx_finding_triage_events_finding_created;

CREATE INDEX IF NOT EXISTS idx_finding_triage_states_scope_status
    ON finding_triage_states (tenant_id, workspace_id, status);

CREATE INDEX IF NOT EXISTS idx_finding_triage_states_scope_assignee
    ON finding_triage_states (tenant_id, workspace_id, assignee);

CREATE INDEX IF NOT EXISTS idx_finding_triage_events_scope_finding_created
    ON finding_triage_events (tenant_id, workspace_id, finding_id, created_at DESC);
