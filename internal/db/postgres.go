package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db/sqlcdb"
	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// PostgresStore persists scans/findings in PostgreSQL.
type PostgresStore struct {
	db      *sql.DB
	queries *sqlcdb.Queries
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
	return &PostgresStore{db: db, queries: sqlcdb.New(db)}, nil
}

// NewPostgresStoreWithDB builds a store around an existing sql.DB (tests).
func NewPostgresStoreWithDB(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db, queries: sqlcdb.New(db)}
}

// DB exposes the underlying sql.DB for runtime wiring (locks, health checks).
func (p *PostgresStore) DB() *sql.DB {
	if p == nil {
		return nil
	}
	return p.db
}

// CreateScan inserts a new scan row.
func (p *PostgresStore) CreateScan(ctx context.Context, provider string, startedAt time.Time) (ScanRecord, error) {
	return p.createScanWithStatus(ctx, provider, "running", startedAt)
}

// CreateQueuedScan inserts a queued scan request row.
func (p *PostgresStore) CreateQueuedScan(ctx context.Context, provider string, queuedAt time.Time) (ScanRecord, error) {
	return p.createScanWithStatus(ctx, provider, "queued", queuedAt)
}

// ClaimNextQueuedScan atomically claims one queued scan for execution.
func (p *PostgresStore) ClaimNextQueuedScan(ctx context.Context, provider string) (ScanRecord, error) {
	row := p.db.QueryRowContext(
		ctx,
		`WITH next_scan AS (
			SELECT id
			FROM scans
			WHERE provider = $1 AND status = 'queued'
			ORDER BY started_at ASC
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE scans AS s
		SET status = 'running',
		    finished_at = NULL,
		    error_message = NULL
		FROM next_scan
		WHERE s.id = next_scan.id
		RETURNING s.id, s.provider, s.status, s.started_at, s.finished_at, s.asset_count, s.finding_count, COALESCE(s.error_message, '')`,
		strings.TrimSpace(provider),
	)
	var record ScanRecord
	var finishedAt sql.NullTime
	if err := row.Scan(
		&record.ID,
		&record.Provider,
		&record.Status,
		&record.StartedAt,
		&finishedAt,
		&record.AssetCount,
		&record.FindingCount,
		&record.ErrorMessage,
	); err != nil {
		if err == sql.ErrNoRows {
			return ScanRecord{}, ErrNotFound
		}
		return ScanRecord{}, fmt.Errorf("claim queued scan: %w", err)
	}
	if finishedAt.Valid {
		converted := finishedAt.Time.UTC()
		record.FinishedAt = &converted
	}
	return record, nil
}

// CountQueuedScans returns queued scan requests count for one provider.
func (p *PostgresStore) CountQueuedScans(ctx context.Context, provider string) (int, error) {
	var count int
	if err := p.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM scans WHERE provider = $1 AND status = 'queued'`,
		strings.TrimSpace(provider),
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("count queued scans: %w", err)
	}
	return count, nil
}

// GetScan returns one scan by id.
func (p *PostgresStore) GetScan(ctx context.Context, scanID string) (ScanRecord, error) {
	row, err := p.queries.GetScan(ctx, scanID)
	if err != nil {
		if err == sql.ErrNoRows {
			return ScanRecord{}, ErrNotFound
		}
		return ScanRecord{}, fmt.Errorf("query scan: %w", err)
	}
	return scanRecordFromRow(row), nil
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
	rows, err := p.queries.ListScans(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("query scans: %w", err)
	}
	result := make([]ScanRecord, 0, len(rows))
	for _, row := range rows {
		result = append(result, scanRecordFromRow(row))
	}
	return result, nil
}

// ListFindings returns latest findings first across scans.
func (p *PostgresStore) ListFindings(ctx context.Context, limit int) ([]domain.Finding, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.queries.ListFindings(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	return findingsFromRows(rows)
}

// ListFindingsByScan returns latest findings first for one scan id.
func (p *PostgresStore) ListFindingsByScan(ctx context.Context, scanID string, limit int) ([]domain.Finding, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.queries.ListFindingsByScan(ctx, scanID, limit)
	if err != nil {
		return nil, fmt.Errorf("query findings by scan: %w", err)
	}
	return findingsFromRows(rows)
}

// ListIdentities returns identities filtered by scan/provider/type/name prefix.
func (p *PostgresStore) ListIdentities(ctx context.Context, filter IdentityFilter, limit int) ([]domain.Identity, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.db.QueryContext(
		ctx,
		`SELECT i.id, i.provider, i.type, i.name, COALESCE(i.arn, ''), COALESCE(i.owner_hint, ''), i.created_at, i.last_used_at, i.tags, i.raw_ref
		 FROM identities i
		 WHERE ($1 = '' OR i.scan_id = $1::uuid)
		   AND ($2 = '' OR i.provider = $2)
		   AND ($3 = '' OR i.type = $3)
		   AND ($4 = '' OR LOWER(i.name) LIKE LOWER($4 || '%'))
		 ORDER BY i.name ASC
		 LIMIT $5`,
		filter.ScanID,
		filter.Provider,
		filter.Type,
		filter.NamePrefix,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query identities: %w", err)
	}
	defer rows.Close()

	result := []domain.Identity{}
	for rows.Next() {
		var identity domain.Identity
		var provider string
		var identityType string
		var arn string
		var ownerHint string
		var createdAt *time.Time
		var tagsJSON []byte
		if err := rows.Scan(&identity.ID, &provider, &identityType, &identity.Name, &arn, &ownerHint, &createdAt, &identity.LastUsedAt, &tagsJSON, &identity.RawRef); err != nil {
			return nil, fmt.Errorf("identity row: %w", err)
		}
		identity.Provider = domain.Provider(provider)
		identity.Type = domain.IdentityType(identityType)
		identity.ARN = arn
		identity.OwnerHint = ownerHint
		if createdAt != nil {
			identity.CreatedAt = createdAt.UTC()
		}
		if len(tagsJSON) > 0 {
			if err := json.Unmarshal(tagsJSON, &identity.Tags); err != nil {
				return nil, fmt.Errorf("decode identity tags: %w", err)
			}
		}
		result = append(result, identity)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("identity rows: %w", err)
	}
	return result, nil
}

// ListRelationships returns relationships filtered by scan/type/from/to.
func (p *PostgresStore) ListRelationships(ctx context.Context, filter RelationshipFilter, limit int) ([]domain.Relationship, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.db.QueryContext(
		ctx,
		`SELECT id, type, from_node_id, to_node_id, COALESCE(evidence_ref, ''), discovered_at
		 FROM relationships
		 WHERE ($1 = '' OR scan_id = $1::uuid)
		   AND ($2 = '' OR type = $2)
		   AND ($3 = '' OR from_node_id = $3)
		   AND ($4 = '' OR to_node_id = $4)
		 ORDER BY discovered_at DESC
		 LIMIT $5`,
		filter.ScanID,
		filter.Type,
		filter.FromNodeID,
		filter.ToNodeID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query relationships: %w", err)
	}
	defer rows.Close()

	result := []domain.Relationship{}
	for rows.Next() {
		var relationship domain.Relationship
		var relationshipType string
		if err := rows.Scan(&relationship.ID, &relationshipType, &relationship.FromNodeID, &relationship.ToNodeID, &relationship.EvidenceRef, &relationship.DiscoveredAt); err != nil {
			return nil, fmt.Errorf("relationship row: %w", err)
		}
		relationship.Type = domain.RelationshipType(relationshipType)
		result = append(result, relationship)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("relationship rows: %w", err)
	}
	return result, nil
}

// AppendScanEvent writes one scan event row.
func (p *PostgresStore) AppendScanEvent(ctx context.Context, scanID string, level string, message string, metadata map[string]any) error {
	normalizedLevel, levelErr := NormalizeScanEventLevel(strings.ToLower(strings.TrimSpace(level)))
	if levelErr != nil {
		return levelErr
	}
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
		normalizedLevel,
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
	rows, err := p.queries.ListScanEvents(ctx, scanID, limit)
	if err != nil {
		return nil, fmt.Errorf("query scan events: %w", err)
	}
	result := []ScanEvent{}
	for _, row := range rows {
		event := ScanEvent{
			ID:        row.ID,
			ScanID:    row.ScanID,
			Level:     row.Level,
			Message:   row.Message,
			CreatedAt: row.CreatedAt,
		}
		if len(row.Metadata) > 0 {
			if err := json.Unmarshal(row.Metadata, &event.Metadata); err != nil {
				return nil, fmt.Errorf("decode scan event metadata: %w", err)
			}
		}
		result = append(result, event)
	}
	return result, nil
}

// CreateRepoScan inserts a new repository exposure scan row.
func (p *PostgresStore) CreateRepoScan(ctx context.Context, repository string, startedAt time.Time) (RepoScanRecord, error) {
	return p.createRepoScanWithStatus(ctx, repository, "running", 0, 0, startedAt)
}

// CreateQueuedRepoScan inserts one queued repository scan request row.
func (p *PostgresStore) CreateQueuedRepoScan(ctx context.Context, repository string, historyLimit int, maxFindings int, queuedAt time.Time) (RepoScanRecord, error) {
	return p.createRepoScanWithStatus(ctx, repository, "queued", historyLimit, maxFindings, queuedAt)
}

// ClaimNextQueuedRepoScan atomically claims one queued repository scan.
func (p *PostgresStore) ClaimNextQueuedRepoScan(ctx context.Context) (RepoScanRecord, error) {
	row := p.db.QueryRowContext(
		ctx,
		`WITH next_repo_scan AS (
			SELECT id
			FROM repo_scans
			WHERE status = 'queued'
			ORDER BY started_at ASC
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE repo_scans AS r
		SET status = 'running',
		    finished_at = NULL,
		    error_message = NULL
		FROM next_repo_scan
		WHERE r.id = next_repo_scan.id
		RETURNING
			r.id,
			r.repository,
			r.status,
			r.started_at,
			r.finished_at,
			r.commits_scanned,
			r.files_scanned,
			r.finding_count,
			r.truncated,
			COALESCE(r.error_message, ''),
			r.history_limit,
			r.max_findings_limit`,
	)
	record, err := scanRepoScanRecord(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return RepoScanRecord{}, ErrNotFound
		}
		return RepoScanRecord{}, fmt.Errorf("claim queued repo scan: %w", err)
	}
	return record, nil
}

// CountQueuedRepoScans returns queued repository scan requests count.
func (p *PostgresStore) CountQueuedRepoScans(ctx context.Context) (int, error) {
	var count int
	if err := p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM repo_scans WHERE status = 'queued'`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count queued repo scans: %w", err)
	}
	return count, nil
}

// CountPendingRepoScansByRepository returns queued+running scan count for one repository.
func (p *PostgresStore) CountPendingRepoScansByRepository(ctx context.Context, repository string) (int, error) {
	var count int
	if err := p.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*)
		 FROM repo_scans
		 WHERE LOWER(repository) = LOWER($1)
		   AND status IN ('queued', 'running')`,
		strings.TrimSpace(repository),
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("count pending repo scans: %w", err)
	}
	return count, nil
}

// RequeueRepoScan moves one running repository scan back to queued.
func (p *PostgresStore) RequeueRepoScan(ctx context.Context, repoScanID string) error {
	result, err := p.db.ExecContext(
		ctx,
		`UPDATE repo_scans
		 SET status = 'queued',
		     started_at = NOW(),
		     finished_at = NULL,
		     error_message = NULL
		 WHERE id = $1
		   AND status = 'running'`,
		repoScanID,
	)
	if err != nil {
		return fmt.Errorf("requeue repo scan: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("requeue repo scan rows affected: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *PostgresStore) createRepoScanWithStatus(ctx context.Context, repository string, status string, historyLimit int, maxFindings int, startedAt time.Time) (RepoScanRecord, error) {
	record := RepoScanRecord{
		ID:           uuid.NewString(),
		Repository:   strings.TrimSpace(repository),
		Status:       strings.TrimSpace(status),
		StartedAt:    startedAt.UTC(),
		HistoryLimit: historyLimit,
		MaxFindings:  maxFindings,
	}
	_, err := p.db.ExecContext(
		ctx,
		`INSERT INTO repo_scans (id, repository, status, started_at, commits_scanned, files_scanned, finding_count, truncated, history_limit, max_findings_limit)
		 VALUES ($1, $2, $3, $4, 0, 0, 0, false, $5, $6)`,
		record.ID,
		record.Repository,
		record.Status,
		record.StartedAt,
		record.HistoryLimit,
		record.MaxFindings,
	)
	if err != nil {
		return RepoScanRecord{}, fmt.Errorf("insert repo scan: %w", err)
	}
	return record, nil
}

// GetRepoScan returns one repository scan by id.
func (p *PostgresStore) GetRepoScan(ctx context.Context, repoScanID string) (RepoScanRecord, error) {
	row, err := p.queries.GetRepoScan(ctx, repoScanID)
	if err != nil {
		if err == sql.ErrNoRows {
			return RepoScanRecord{}, ErrNotFound
		}
		return RepoScanRecord{}, fmt.Errorf("query repo scan: %w", err)
	}
	return repoScanRecordFromRow(row), nil
}

// CompleteRepoScan updates repository scan completion metadata.
func (p *PostgresStore) CompleteRepoScan(ctx context.Context, repoScanID string, status string, finishedAt time.Time, commitsScanned int, filesScanned int, findingCount int, truncated bool, errorMessage string) error {
	_, err := p.db.ExecContext(
		ctx,
		`UPDATE repo_scans
		 SET status = $2,
		     finished_at = $3,
		     commits_scanned = $4,
		     files_scanned = $5,
		     finding_count = $6,
		     truncated = $7,
		     error_message = $8
		 WHERE id = $1`,
		repoScanID,
		strings.TrimSpace(status),
		finishedAt.UTC(),
		commitsScanned,
		filesScanned,
		findingCount,
		truncated,
		nullableString(errorMessage),
	)
	if err != nil {
		return fmt.Errorf("complete repo scan: %w", err)
	}
	return nil
}

// UpsertRepoFindings inserts repository findings idempotently.
func (p *PostgresStore) UpsertRepoFindings(ctx context.Context, repoScanID string, findings []domain.Finding) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin repo findings transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := `
		INSERT INTO repo_findings (repo_scan_id, finding_id, type, severity, title, human_summary, path, evidence, remediation, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (repo_scan_id, finding_id)
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
		pathJSON, pathErr := json.Marshal(finding.Path)
		if pathErr != nil {
			return fmt.Errorf("marshal repo finding path: %w", pathErr)
		}
		evidenceJSON, evidenceErr := json.Marshal(finding.Evidence)
		if evidenceErr != nil {
			return fmt.Errorf("marshal repo finding evidence: %w", evidenceErr)
		}
		createdAt := finding.CreatedAt
		if createdAt.IsZero() {
			createdAt = time.Now().UTC()
		}
		_, execErr := tx.ExecContext(
			ctx,
			query,
			repoScanID,
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
		if execErr != nil {
			return fmt.Errorf("upsert repo finding %s: %w", finding.ID, execErr)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit repo findings transaction: %w", err)
	}
	return nil
}

// ListRepoScans returns latest repository scans first.
func (p *PostgresStore) ListRepoScans(ctx context.Context, limit int) ([]RepoScanRecord, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := p.queries.ListRepoScans(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("query repo scans: %w", err)
	}
	result := make([]RepoScanRecord, 0, len(rows))
	for _, row := range rows {
		result = append(result, repoScanRecordFromRow(row))
	}
	return result, nil
}

// ListRepoFindings returns latest repository findings first with optional filters.
func (p *PostgresStore) ListRepoFindings(ctx context.Context, filter RepoFindingFilter, limit int) ([]domain.Finding, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.queries.ListRepoFindings(
		ctx,
		strings.TrimSpace(filter.RepoScanID),
		strings.TrimSpace(filter.Severity),
		strings.TrimSpace(filter.Type),
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query repo findings: %w", err)
	}
	result := make([]domain.Finding, 0, len(rows))
	for _, row := range rows {
		finding := domain.Finding{
			ScanID:       row.RepoScanID,
			ID:           row.FindingID,
			Type:         domain.FindingType(row.Type),
			Severity:     domain.FindingSeverity(row.Severity),
			Title:        row.Title,
			HumanSummary: row.HumanSummary,
			Remediation:  row.Remediation,
			CreatedAt:    row.CreatedAt,
		}
		if len(row.Path) > 0 {
			if err := json.Unmarshal(row.Path, &finding.Path); err != nil {
				return nil, fmt.Errorf("decode repo finding path: %w", err)
			}
		}
		if len(row.Evidence) > 0 {
			if err := json.Unmarshal(row.Evidence, &finding.Evidence); err != nil {
				return nil, fmt.Errorf("decode repo finding evidence: %w", err)
			}
		}
		result = append(result, finding)
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

func scanRecordFromRow(row sqlcdb.ScanRow) ScanRecord {
	return ScanRecord{
		ID:           row.ID,
		Provider:     row.Provider,
		Status:       row.Status,
		StartedAt:    row.StartedAt,
		FinishedAt:   row.FinishedAt,
		AssetCount:   row.AssetCount,
		FindingCount: row.FindingCount,
		ErrorMessage: row.ErrorMessage,
	}
}

func repoScanRecordFromRow(row sqlcdb.RepoScanRow) RepoScanRecord {
	return RepoScanRecord{
		ID:             row.ID,
		Repository:     row.Repository,
		Status:         row.Status,
		StartedAt:      row.StartedAt.UTC(),
		FinishedAt:     row.FinishedAt,
		CommitsScanned: row.CommitsScanned,
		FilesScanned:   row.FilesScanned,
		FindingCount:   row.FindingCount,
		Truncated:      row.Truncated,
		ErrorMessage:   row.ErrorMessage,
	}
}

func (p *PostgresStore) createScanWithStatus(ctx context.Context, provider string, status string, startedAt time.Time) (ScanRecord, error) {
	record := ScanRecord{
		ID:        uuid.NewString(),
		Provider:  strings.TrimSpace(provider),
		Status:    strings.TrimSpace(status),
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

type scanner interface {
	Scan(dest ...any) error
}

func scanRepoScanRecord(scanner scanner) (RepoScanRecord, error) {
	var record RepoScanRecord
	var finishedAt sql.NullTime
	if err := scanner.Scan(
		&record.ID,
		&record.Repository,
		&record.Status,
		&record.StartedAt,
		&finishedAt,
		&record.CommitsScanned,
		&record.FilesScanned,
		&record.FindingCount,
		&record.Truncated,
		&record.ErrorMessage,
		&record.HistoryLimit,
		&record.MaxFindings,
	); err != nil {
		return RepoScanRecord{}, err
	}
	record.StartedAt = record.StartedAt.UTC()
	if finishedAt.Valid {
		converted := finishedAt.Time.UTC()
		record.FinishedAt = &converted
	}
	return record, nil
}

func findingsFromRows(rows []sqlcdb.FindingRow) ([]domain.Finding, error) {
	result := make([]domain.Finding, 0, len(rows))
	for _, row := range rows {
		finding := domain.Finding{
			ScanID:       row.ScanID,
			ID:           row.FindingID,
			Type:         domain.FindingType(row.Type),
			Severity:     domain.FindingSeverity(row.Severity),
			Title:        row.Title,
			HumanSummary: row.HumanSummary,
			Remediation:  row.Remediation,
			CreatedAt:    row.CreatedAt,
		}
		if len(row.Path) > 0 {
			if err := json.Unmarshal(row.Path, &finding.Path); err != nil {
				return nil, fmt.Errorf("decode finding path: %w", err)
			}
		}
		if len(row.Evidence) > 0 {
			if err := json.Unmarshal(row.Evidence, &finding.Evidence); err != nil {
				return nil, fmt.Errorf("decode finding evidence: %w", err)
			}
		}
		result = append(result, finding)
	}
	return result, nil
}
