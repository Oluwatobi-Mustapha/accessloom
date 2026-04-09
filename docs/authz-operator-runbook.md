# AuthZ Operator Runbook

This runbook is for operators and compliance teams managing centralized authorization in production.
It focuses on safe operation, explainability, and incident handling for policy decisions.

## Scope

This runbook covers:
- decision audit logging verification
- explainability checks (`stage` + `reason`)
- rollout safety checks and rollback execution
- evidence collection for audit/compliance workflows

For rollout semantics, see [AuthZ Policy Rollout Runbook](./authz-policy-rollout-runbook.md).

## Prerequisites

- Auth enabled with scoped keys (`read`/`write`/`admin`) or equivalent OIDC mapping.
- Tenant/workspace scoping enforced in requests.
- Audit sink configured:
  - local JSONL: `IDENTRAIL_AUDIT_LOG_FILE`
  - optional remote forwarding: `IDENTRAIL_AUDIT_FORWARD_URL`
- Admin credential available for policy simulation/rollback endpoints.

## 1. Verify Decision Audit Logging

Every protected route decision should produce an audit entry with `authz` payload.

Example verification command:

```bash
tail -n 200 "${IDENTRAIL_AUDIT_LOG_FILE}" \
  | jq -c 'select(.authz != null) | .authz | {
      policy_set_id,
      policy_version,
      policy_source,
      rollout_mode,
      allowed,
      stage,
      reason,
      input
    }'
```

If running via Docker Compose, read the file from the API container:

```bash
docker exec identrail-api sh -lc 'tail -n 200 /tmp/identrail-audit.jsonl'
```

Expected `authz.input` fields:
- `subject_type`
- `subject_id_hash`
- `action`
- `resource_type`
- `resource_id_hash`
- `tenant_id`
- `workspace_id`

Guardrail:
- IDs are hashed (`*_id_hash`), so raw subject/resource identifiers should not appear in audit output.

## 2. Explainability Checks (Per Deploy)

Run a controlled simulation request and verify decision trace ordering:
`tenant_isolation -> rbac -> abac -> rebac -> default_deny`.

Example:

```bash
curl -sS -X POST "http://localhost:8080/v1/authz/policies/simulate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${IDENTRAIL_ADMIN_KEY}" \
  -H "X-Identrail-Tenant-ID: ${IDENTRAIL_TENANT_ID}" \
  -H "X-Identrail-Workspace-ID: ${IDENTRAIL_WORKSPACE_ID}" \
  -d '{
    "subject": {
      "type": "subject",
      "id": "ops-user",
      "tenant_id": "'"${IDENTRAIL_TENANT_ID}"'",
      "workspace_id": "'"${IDENTRAIL_WORKSPACE_ID}"'",
      "roles": ["admin"]
    },
    "action": "findings.read",
    "resource": {
      "type": "finding",
      "id": "finding-1",
      "tenant_id": "'"${IDENTRAIL_TENANT_ID}"'",
      "workspace_id": "'"${IDENTRAIL_WORKSPACE_ID}"'"
    },
    "context": {
      "request_path": "/v1/findings",
      "request_method": "GET"
    }
  }' | jq '{decision, trace}'
```

Validate:
- response includes `decision.allowed`, `decision.stage`, `decision.reason`
- response includes full `trace` with stage outcomes
- deny outcomes are explainable by stage and reason

## 3. Runtime Metrics to Monitor

Scrape `GET /metrics` and track:
- `identrail_authz_policy_decisions_by_version_total`
- `identrail_authz_policy_rollout_shadow_evaluations_total`
- `identrail_authz_policy_rollout_shadow_divergences_total`
- `identrail_authz_policy_rollout_shadow_divergence_rate`
- `identrail_authz_policy_rollout_shadow_evaluation_errors_total`
- `identrail_authz_policy_rollout_rollbacks_total`

Minimum alarms:
- divergence rate spike during shadow rollout
- sudden deny-rate increase by policy version
- any rollback event outside planned change windows

## 4. Emergency Rollback Procedure

Use either API or CLI to force one-call rollback to a known-safe version.

CLI:

```bash
identrail authz rollback \
  --api-url "http://localhost:8080" \
  --api-key "${IDENTRAIL_ADMIN_KEY}" \
  --tenant-id "${IDENTRAIL_TENANT_ID}" \
  --workspace-id "${IDENTRAIL_WORKSPACE_ID}" \
  --policy-set-id central_authorization \
  --target-version 1 \
  --actor "subject:ops-oncall"
```

Post-rollback checks:
- rollout mode is `disabled`
- active version equals target version
- decision counters move back to rolled-back version
- deny/allow ratios return to baseline

## 5. Compliance Evidence Checklist

For each policy change window, archive:
- simulation request/response JSON (`decision` + `trace`)
- rollout mode change records
- rollback event records (if any)
- authz decision audit samples (allow + deny)
- metric snapshots for divergence and decision counters

This provides reproducible evidence for access-control governance reviews.
