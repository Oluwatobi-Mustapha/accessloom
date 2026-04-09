# Observability Baseline

Identrail exposes logs, metrics, and tracing hooks from day one.

## Logs

- Structured logs via Zap across API, worker, scheduler, and providers.
- Scan lifecycle errors are persisted as scan events and also logged.

## Metrics

Scrape `GET /metrics`.

Core scan metrics:
- `identrail_scan_runs_total`
- `identrail_scan_success_total`
- `identrail_scan_failure_total`
- `identrail_scan_partial_total`
- `identrail_scan_in_flight`
- `identrail_scan_duration_milliseconds`

Risk output metric:
- `identrail_analysis_findings_generated_total`

Repository scan metrics:
- `identrail_repo_scan_runs_total`
- `identrail_repo_scan_failure_total`
- `identrail_repo_scan_duration_milliseconds`

Authorization policy lifecycle metrics:
- `identrail_authz_policy_decisions_by_version_total`
- `identrail_authz_policy_rollout_shadow_evaluations_total`
- `identrail_authz_policy_rollout_shadow_divergences_total`
- `identrail_authz_policy_rollout_shadow_divergence_rate`
- `identrail_authz_policy_rollout_shadow_evaluation_errors_total`
- `identrail_authz_policy_rollout_rollbacks_total`

## Tracing

- Scanner pipeline emits OpenTelemetry spans:
  - `scanner.run`
  - `scanner.collect`
  - `scanner.normalize`
  - `scanner.permissions`
  - `scanner.relationships`
  - `scanner.risk`

## V1 SLOs

- Scan success rate: >= 99% over rolling 24h (excluding known provider outages).
- API p95 latency for list endpoints: <= 300ms under normal load.
- Worker scheduled run reliability: >= 99% successful schedule executions per day.
- Backlog recovery: queue drains to steady state within 30 minutes after outage.

## Alert Triggers (Recommended)

- `identrail_scan_failure_total` increase > 3 in 10 minutes.
- `identrail_scan_partial_total` increase > 5 in 30 minutes.
- `identrail_scan_in_flight` stuck > 1 for 10 minutes.
- API p95 latency above SLO for 15 minutes.
