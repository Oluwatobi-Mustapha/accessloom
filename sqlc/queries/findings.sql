-- name: ListFindings :many
SELECT scan_id, finding_id, type, severity, title, human_summary, path, evidence, remediation, created_at
FROM findings
ORDER BY created_at DESC
LIMIT $1;

-- name: ListFindingsByScan :many
SELECT scan_id, finding_id, type, severity, title, human_summary, path, evidence, remediation, created_at
FROM findings
WHERE scan_id = $1
ORDER BY created_at DESC
LIMIT $2;
