-- name: ListIdentities :many
SELECT i.id, i.provider, i.type, i.name, COALESCE(i.arn, '') AS arn, COALESCE(i.owner_hint, '') AS owner_hint, i.created_at, i.last_used_at, i.tags, i.raw_ref
FROM identities i
WHERE ($1 = '' OR i.scan_id = $1::uuid)
  AND ($2 = '' OR i.provider = $2)
  AND ($3 = '' OR i.type = $3)
  AND ($4 = '' OR LOWER(i.name) LIKE LOWER($4 || '%'))
ORDER BY i.name ASC
LIMIT $5;

-- name: ListRelationships :many
SELECT id, type, from_node_id, to_node_id, COALESCE(evidence_ref, '') AS evidence_ref, discovered_at
FROM relationships
WHERE ($1 = '' OR scan_id = $1::uuid)
  AND ($2 = '' OR type = $2)
  AND ($3 = '' OR from_node_id = $3)
  AND ($4 = '' OR to_node_id = $4)
ORDER BY discovered_at DESC
LIMIT $5;
