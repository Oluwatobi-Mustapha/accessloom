-- name: GetRepoScan :one
SELECT id, repository, status, started_at, finished_at, commits_scanned, files_scanned, finding_count, truncated, COALESCE(error_message, '') AS error_message
FROM repo_scans
WHERE id = $1;

-- name: ListRepoScans :many
SELECT id, repository, status, started_at, finished_at, commits_scanned, files_scanned, finding_count, truncated, COALESCE(error_message, '') AS error_message
FROM repo_scans
ORDER BY started_at DESC
LIMIT $1;

-- name: ListRepoFindings :many
SELECT repo_scan_id, finding_id, type, severity, title, human_summary, path, evidence, remediation, created_at
FROM repo_findings
WHERE ($1 = '' OR repo_scan_id = $1::uuid)
  AND ($2 = '' OR severity = $2)
  AND ($3 = '' OR type = $3)
ORDER BY created_at DESC
LIMIT $4;
