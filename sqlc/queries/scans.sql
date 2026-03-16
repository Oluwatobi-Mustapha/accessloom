-- name: GetScan :one
SELECT id, provider, status, started_at, finished_at, asset_count, finding_count, COALESCE(error_message, '') AS error_message
FROM scans
WHERE id = $1;

-- name: ListScans :many
SELECT id, provider, status, started_at, finished_at, asset_count, finding_count, COALESCE(error_message, '') AS error_message
FROM scans
ORDER BY started_at DESC
LIMIT $1;
