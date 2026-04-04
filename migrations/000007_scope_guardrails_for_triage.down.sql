DROP INDEX IF EXISTS idx_finding_triage_events_scope_finding_created;
DROP INDEX IF EXISTS idx_finding_triage_states_scope_assignee;
DROP INDEX IF EXISTS idx_finding_triage_states_scope_status;

CREATE INDEX IF NOT EXISTS idx_finding_triage_states_status
    ON finding_triage_states (status);

CREATE INDEX IF NOT EXISTS idx_finding_triage_states_assignee
    ON finding_triage_states (assignee);

CREATE INDEX IF NOT EXISTS idx_finding_triage_events_finding_created
    ON finding_triage_events (finding_id, created_at DESC);

WITH ranked_states AS (
    SELECT
        ctid,
        ROW_NUMBER() OVER (
            PARTITION BY finding_id
            ORDER BY updated_at DESC, tenant_id ASC, workspace_id ASC
        ) AS row_rank
    FROM finding_triage_states
)
DELETE FROM finding_triage_states s
USING ranked_states r
WHERE s.ctid = r.ctid
  AND r.row_rank > 1;

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
