package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
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
