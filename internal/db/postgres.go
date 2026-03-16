package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// PostgresStore persists scans/findings in PostgreSQL.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore opens a PostgreSQL connection and validates connectivity.
func NewPostgresStore(databaseURL string) (*PostgresStore, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	// Conservative pool defaults reduce misconfiguration risk in early deployments.
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &PostgresStore{db: db}, nil
}

// NewPostgresStoreWithDB builds a store around an existing sql.DB (tests).
func NewPostgresStoreWithDB(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

// CreateScan inserts a new scan row.
func (p *PostgresStore) CreateScan(ctx context.Context, provider string, startedAt time.Time) (ScanRecord, error) {
	record := ScanRecord{
		ID:        uuid.NewString(),
		Provider:  provider,
		Status:    "running",
		StartedAt: startedAt.UTC(),
	}

	_, err := p.db.ExecContext(
		ctx,
		`INSERT INTO scans (id, provider, status, started_at, asset_count, finding_count) VALUES ($1, $2, $3, $4, 0, 0)`,
		record.ID,
		record.Provider,
		record.Status,
		record.StartedAt,
	)
	if err != nil {
		return ScanRecord{}, fmt.Errorf("insert scan: %w", err)
	}
	return record, nil
}

// GetScan returns one scan by id.
func (p *PostgresStore) GetScan(ctx context.Context, scanID string) (ScanRecord, error) {
	var record ScanRecord
	err := p.db.QueryRowContext(
		ctx,
		`SELECT id, provider, status, started_at, finished_at, asset_count, finding_count, COALESCE(error_message, '')
		 FROM scans
		 WHERE id = $1`,
		scanID,
	).Scan(&record.ID, &record.Provider, &record.Status, &record.StartedAt, &record.FinishedAt, &record.AssetCount, &record.FindingCount, &record.ErrorMessage)
	if err != nil {
		if err == sql.ErrNoRows {
			return ScanRecord{}, ErrNotFound
		}
		return ScanRecord{}, fmt.Errorf("query scan: %w", err)
	}
	return record, nil
}

// CompleteScan updates scan completion metadata.
func (p *PostgresStore) CompleteScan(ctx context.Context, scanID string, status string, finishedAt time.Time, assetCount int, findingCount int, errorMessage string) error {
	_, err := p.db.ExecContext(
		ctx,
		`UPDATE scans SET status=$2, finished_at=$3, asset_count=$4, finding_count=$5, error_message=$6 WHERE id=$1`,
		scanID,
		status,
		finishedAt.UTC(),
		assetCount,
		findingCount,
		nullableString(errorMessage),
	)
	if err != nil {
		return fmt.Errorf("complete scan: %w", err)
	}
	return nil
}

// UpsertArtifacts inserts raw and normalized artifacts idempotently for one scan.
func (p *PostgresStore) UpsertArtifacts(ctx context.Context, scanID string, artifacts ScanArtifacts) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin artifacts transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := upsertRawAssets(ctx, tx, scanID, artifacts.RawAssets); err != nil {
		return err
	}
	if err := upsertIdentities(ctx, tx, scanID, artifacts.Bundle.Identities); err != nil {
		return err
	}
	if err := upsertPolicies(ctx, tx, scanID, artifacts.Bundle.Policies); err != nil {
		return err
	}
	if err := upsertRelationships(ctx, tx, scanID, artifacts.Relationships); err != nil {
		return err
	}
	if err := upsertPermissions(ctx, tx, scanID, artifacts.Permissions); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit artifacts transaction: %w", err)
	}
	return nil
}

// UpsertFindings inserts findings idempotently for the scan.
func (p *PostgresStore) UpsertFindings(ctx context.Context, scanID string, findings []domain.Finding) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := `
		INSERT INTO findings (scan_id, finding_id, type, severity, title, human_summary, path, evidence, remediation, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (scan_id, finding_id)
		DO UPDATE SET
		  type = EXCLUDED.type,
		  severity = EXCLUDED.severity,
		  title = EXCLUDED.title,
		  human_summary = EXCLUDED.human_summary,
		  path = EXCLUDED.path,
		  evidence = EXCLUDED.evidence,
		  remediation = EXCLUDED.remediation,
		  created_at = EXCLUDED.created_at
	`

	for _, finding := range findings {
		pathJSON, err := json.Marshal(finding.Path)
		if err != nil {
			return fmt.Errorf("marshal finding path: %w", err)
		}
		evidenceJSON, err := json.Marshal(finding.Evidence)
		if err != nil {
			return fmt.Errorf("marshal finding evidence: %w", err)
		}

		createdAt := finding.CreatedAt
		if createdAt.IsZero() {
			createdAt = time.Now().UTC()
		}

		_, err = tx.ExecContext(
			ctx,
			query,
			scanID,
			finding.ID,
			string(finding.Type),
			string(finding.Severity),
			finding.Title,
			finding.HumanSummary,
			pathJSON,
			evidenceJSON,
			finding.Remediation,
			createdAt.UTC(),
		)
		if err != nil {
			return fmt.Errorf("upsert finding %s: %w", finding.ID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit findings transaction: %w", err)
	}
	return nil
}

// ListScans returns latest scans first.
func (p *PostgresStore) ListScans(ctx context.Context, limit int) ([]ScanRecord, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := p.db.QueryContext(
		ctx,
		`SELECT id, provider, status, started_at, finished_at, asset_count, finding_count, COALESCE(error_message, '')
		 FROM scans
		 ORDER BY started_at DESC
		 LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query scans: %w", err)
	}
	defer rows.Close()

	result := []ScanRecord{}
	for rows.Next() {
		var record ScanRecord
		if err := rows.Scan(&record.ID, &record.Provider, &record.Status, &record.StartedAt, &record.FinishedAt, &record.AssetCount, &record.FindingCount, &record.ErrorMessage); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan rows: %w", err)
	}
	return result, nil
}

// ListFindings returns latest findings first across scans.
func (p *PostgresStore) ListFindings(ctx context.Context, limit int) ([]domain.Finding, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.db.QueryContext(
		ctx,
		`SELECT scan_id, finding_id, type, severity, title, human_summary, path, evidence, remediation, created_at
		 FROM findings
		 ORDER BY created_at DESC
		 LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()

	result := []domain.Finding{}
	for rows.Next() {
		var finding domain.Finding
		var findingType string
		var severity string
		var pathJSON []byte
		var evidenceJSON []byte
		if err := rows.Scan(&finding.ScanID, &finding.ID, &findingType, &severity, &finding.Title, &finding.HumanSummary, &pathJSON, &evidenceJSON, &finding.Remediation, &finding.CreatedAt); err != nil {
			return nil, fmt.Errorf("finding row: %w", err)
		}
		finding.Type = domain.FindingType(findingType)
		finding.Severity = domain.FindingSeverity(severity)
		if len(pathJSON) > 0 {
			if err := json.Unmarshal(pathJSON, &finding.Path); err != nil {
				return nil, fmt.Errorf("decode finding path: %w", err)
			}
		}
		if len(evidenceJSON) > 0 {
			if err := json.Unmarshal(evidenceJSON, &finding.Evidence); err != nil {
				return nil, fmt.Errorf("decode finding evidence: %w", err)
			}
		}
		result = append(result, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("finding rows: %w", err)
	}
	return result, nil
}

// ListFindingsByScan returns latest findings first for one scan id.
func (p *PostgresStore) ListFindingsByScan(ctx context.Context, scanID string, limit int) ([]domain.Finding, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.db.QueryContext(
		ctx,
		`SELECT scan_id, finding_id, type, severity, title, human_summary, path, evidence, remediation, created_at
		 FROM findings
		 WHERE scan_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2`,
		scanID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query findings by scan: %w", err)
	}
	defer rows.Close()

	result := []domain.Finding{}
	for rows.Next() {
		var finding domain.Finding
		var findingType string
		var severity string
		var pathJSON []byte
		var evidenceJSON []byte
		if err := rows.Scan(&finding.ScanID, &finding.ID, &findingType, &severity, &finding.Title, &finding.HumanSummary, &pathJSON, &evidenceJSON, &finding.Remediation, &finding.CreatedAt); err != nil {
			return nil, fmt.Errorf("finding row: %w", err)
		}
		finding.Type = domain.FindingType(findingType)
		finding.Severity = domain.FindingSeverity(severity)
		if len(pathJSON) > 0 {
			if err := json.Unmarshal(pathJSON, &finding.Path); err != nil {
				return nil, fmt.Errorf("decode finding path: %w", err)
			}
		}
		if len(evidenceJSON) > 0 {
			if err := json.Unmarshal(evidenceJSON, &finding.Evidence); err != nil {
				return nil, fmt.Errorf("decode finding evidence: %w", err)
			}
		}
		result = append(result, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("finding rows: %w", err)
	}
	return result, nil
}

// AppendScanEvent writes one scan event row.
func (p *PostgresStore) AppendScanEvent(ctx context.Context, scanID string, level string, message string, metadata map[string]any) error {
	payload, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("marshal scan event metadata: %w", err)
	}
	_, err = p.db.ExecContext(
		ctx,
		`INSERT INTO scan_events (id, scan_id, level, message, metadata, created_at)
		 VALUES ($1, $2, $3, $4, $5, NOW())`,
		uuid.NewString(),
		scanID,
		level,
		message,
		payload,
	)
	if err != nil {
		return fmt.Errorf("insert scan event: %w", err)
	}
	return nil
}

// ListScanEvents returns latest event entries for one scan.
func (p *PostgresStore) ListScanEvents(ctx context.Context, scanID string, limit int) ([]ScanEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.db.QueryContext(
		ctx,
		`SELECT id, scan_id, level, message, metadata, created_at
		 FROM scan_events
		 WHERE scan_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2`,
		scanID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query scan events: %w", err)
	}
	defer rows.Close()

	result := []ScanEvent{}
	for rows.Next() {
		var event ScanEvent
		var metadataJSON []byte
		if err := rows.Scan(&event.ID, &event.ScanID, &event.Level, &event.Message, &metadataJSON, &event.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan event row: %w", err)
		}
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &event.Metadata); err != nil {
				return nil, fmt.Errorf("decode scan event metadata: %w", err)
			}
		}
		result = append(result, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan event rows: %w", err)
	}
	return result, nil
}

// Close closes database resources.
func (p *PostgresStore) Close() error {
	if p.db == nil {
		return nil
	}
	return p.db.Close()
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

func upsertRawAssets(ctx context.Context, tx *sql.Tx, scanID string, assets []providers.RawAsset) error {
	query := `
		INSERT INTO raw_assets (scan_id, source_id, kind, payload, collected_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (scan_id, source_id, kind)
		DO UPDATE SET payload = EXCLUDED.payload, collected_at = EXCLUDED.collected_at
	`
	for _, asset := range assets {
		collectedAt, err := time.Parse(time.RFC3339Nano, asset.Collected)
		if err != nil {
			collectedAt = time.Now().UTC()
		}
		_, err = tx.ExecContext(ctx, query, scanID, asset.SourceID, asset.Kind, asset.Payload, collectedAt.UTC())
		if err != nil {
			return fmt.Errorf("upsert raw asset %s: %w", asset.SourceID, err)
		}
	}
	return nil
}

func upsertIdentities(ctx context.Context, tx *sql.Tx, scanID string, identities []domain.Identity) error {
	query := `
		INSERT INTO identities (scan_id, id, provider, type, name, arn, owner_hint, created_at, last_used_at, tags, raw_ref, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
		ON CONFLICT (scan_id, id)
		DO UPDATE SET
		  provider = EXCLUDED.provider,
		  type = EXCLUDED.type,
		  name = EXCLUDED.name,
		  arn = EXCLUDED.arn,
		  owner_hint = EXCLUDED.owner_hint,
		  created_at = EXCLUDED.created_at,
		  last_used_at = EXCLUDED.last_used_at,
		  tags = EXCLUDED.tags,
		  raw_ref = EXCLUDED.raw_ref,
		  updated_at = NOW()
	`
	for _, identity := range identities {
		tagsJSON, err := json.Marshal(identity.Tags)
		if err != nil {
			return fmt.Errorf("marshal identity tags: %w", err)
		}
		_, err = tx.ExecContext(
			ctx,
			query,
			scanID,
			identity.ID,
			string(identity.Provider),
			string(identity.Type),
			identity.Name,
			nullableString(identity.ARN),
			nullableString(identity.OwnerHint),
			nullableTime(identity.CreatedAt),
			identity.LastUsedAt,
			tagsJSON,
			identity.RawRef,
		)
		if err != nil {
			return fmt.Errorf("upsert identity %s: %w", identity.ID, err)
		}
	}
	return nil
}

func upsertPolicies(ctx context.Context, tx *sql.Tx, scanID string, policies []domain.Policy) error {
	query := `
		INSERT INTO policies (scan_id, id, provider, name, document, normalized, raw_ref, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		ON CONFLICT (scan_id, id)
		DO UPDATE SET
		  provider = EXCLUDED.provider,
		  name = EXCLUDED.name,
		  document = EXCLUDED.document,
		  normalized = EXCLUDED.normalized,
		  raw_ref = EXCLUDED.raw_ref,
		  updated_at = NOW()
	`
	for _, policy := range policies {
		normalizedJSON, err := json.Marshal(policy.Normalized)
		if err != nil {
			return fmt.Errorf("marshal policy normalized: %w", err)
		}
		_, err = tx.ExecContext(
			ctx,
			query,
			scanID,
			policy.ID,
			string(policy.Provider),
			policy.Name,
			string(policy.Document),
			normalizedJSON,
			policy.RawRef,
		)
		if err != nil {
			return fmt.Errorf("upsert policy %s: %w", policy.ID, err)
		}
	}
	return nil
}

func upsertRelationships(ctx context.Context, tx *sql.Tx, scanID string, relationships []domain.Relationship) error {
	query := `
		INSERT INTO relationships (scan_id, id, type, from_node_id, to_node_id, evidence_ref, discovered_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (scan_id, id)
		DO UPDATE SET
		  type = EXCLUDED.type,
		  from_node_id = EXCLUDED.from_node_id,
		  to_node_id = EXCLUDED.to_node_id,
		  evidence_ref = EXCLUDED.evidence_ref,
		  discovered_at = EXCLUDED.discovered_at
	`
	for _, relationship := range relationships {
		_, err := tx.ExecContext(
			ctx,
			query,
			scanID,
			relationship.ID,
			string(relationship.Type),
			relationship.FromNodeID,
			relationship.ToNodeID,
			nullableString(relationship.EvidenceRef),
			relationship.DiscoveredAt.UTC(),
		)
		if err != nil {
			return fmt.Errorf("upsert relationship %s: %w", relationship.ID, err)
		}
	}
	return nil
}

func upsertPermissions(ctx context.Context, tx *sql.Tx, scanID string, permissions []providers.PermissionTuple) error {
	query := `
		INSERT INTO permissions (scan_id, identity_id, action, resource, effect)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (scan_id, identity_id, action, resource, effect)
		DO NOTHING
	`
	for _, permission := range permissions {
		_, err := tx.ExecContext(
			ctx,
			query,
			scanID,
			permission.IdentityID,
			permission.Action,
			permission.Resource,
			permission.Effect,
		)
		if err != nil {
			return fmt.Errorf("upsert permission for %s: %w", permission.IdentityID, err)
		}
	}
	return nil
}
