# AuthZ Policy Rollout Runbook

This runbook defines the safe lifecycle for central authorization policy rollout:
`activate -> shadow -> enforce -> rollback`.

## Preconditions

- Policy set exists (`central_authorization` by default).
- Target policy bundle version compiles successfully.
- Rollout `validated_versions` includes any version that may be enforced.
- Admin credentials are available (`admin` scope / API key).

## Rollout Modes

- `disabled`: enforce active version only.
- `shadow`: enforce active version, evaluate candidate in parallel for divergence telemetry.
- `enforce`: targeted traffic evaluates candidate policy directly.

## Phase 1: Activate

1. Set `active_version` to the current safe baseline.
2. Keep rollout mode `disabled`.
3. Confirm decision-by-version metric increments for active version.

Operational checks:
- `identrail_authz_policy_decisions_by_version_total{policy_version="<active>",allowed="true"}`

## Phase 2: Shadow

1. Set `candidate_version`.
2. Set mode `shadow`.
3. Apply tenant/workspace allowlists and canary percentage.
4. Observe divergence and error metrics.

Operational checks:
- `identrail_authz_policy_rollout_shadow_evaluations_total`
- `identrail_authz_policy_rollout_shadow_divergences_total`
- `identrail_authz_policy_rollout_shadow_divergence_rate`
- `identrail_authz_policy_rollout_shadow_evaluation_errors_total`

## Phase 3: Enforce

1. Ensure candidate version exists in `validated_versions`.
2. Set mode `enforce`.
3. Keep targeting constraints (allowlists + canary) for progressive rollout.

Operational checks:
- Decision counters for candidate version increase.
- Denied/allowed ratios remain within expected bounds per tenant/workspace.

## Phase 4: Rollback

Rollback is one API call and immediately resets rollout mode to `disabled` while switching active version.

### API

- Endpoint: `POST /v1/authz/policies/rollback`
- Request body:

```json
{
  "policy_set_id": "central_authorization",
  "target_version": 1,
  "actor": "subject:ops-oncall"
}
```

- Behavior:
  - sets `active_version = target_version`
  - clears `candidate_version`
  - sets `mode = disabled`
  - increments rollback metric

### CLI

```bash
identrail authz rollback \
  --api-url http://127.0.0.1:8080 \
  --api-key "$IDENTRAIL_API_KEY" \
  --tenant-id default \
  --workspace-id default \
  --policy-set-id central_authorization \
  --target-version 1
```

Operational checks:
- `identrail_authz_policy_rollout_rollbacks_total`
- decision-by-version metric should shift back to rolled-back version.

## Incident Notes

- If shadow divergence spikes, do not move to enforce.
- If enforce causes elevated deny rates or customer impact, execute rollback immediately.
- Always capture rollback actor and incident link in change records.
