-- name: InsertScanEvent :exec
INSERT INTO scan_events (id, scan_id, level, message, metadata, created_at)
VALUES ($1, $2, $3, $4, $5, NOW());

-- name: ListScanEvents :many
SELECT id, scan_id, level, message, metadata, created_at
FROM scan_events
WHERE scan_id = $1
ORDER BY created_at DESC
LIMIT $2;
