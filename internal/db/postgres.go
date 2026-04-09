package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
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
	db              *sql.DB
	queries         *sqlcdb.Queries
	enforceScopeRLS bool
}

type sqlExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type rowScanner interface {
	Scan(dest ...any) error
}

type errScanner struct {
	err error
}

func (e errScanner) Scan(_ ...any) error {
	return e.err
}

var placeholderPattern = regexp.MustCompile(`\$(\d+)`)

var errQueryArgCapacityOverflow = errors.New("query argument capacity overflow")

func checkedSliceCapacity(base int, extra int) (int, error) {
	if base < 0 || extra < 0 {
		return 0, fmt.Errorf("invalid slice capacity inputs")
	}
	maxInt := int(^uint(0) >> 1)
	if base > maxInt-extra {
		return 0, errQueryArgCapacityOverflow
	}
	return base + extra, nil
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

// SetScopeRLSEnforcement toggles statement-level RLS enforcement with scoped GUCs.
func (p *PostgresStore) SetScopeRLSEnforcement(enabled bool) {
	if p == nil {
		return
	}
	p.enforceScopeRLS = enabled
}

// ScopeRLSEnforcementEnabled returns true when scoped RLS enforcement is enabled.
func (p *PostgresStore) ScopeRLSEnforcementEnabled() bool {
	if p == nil {
		return false
	}
	return p.enforceScopeRLS
}

func (p *PostgresStore) injectScopeCTE(ctx context.Context, query string, args []any) (string, []any, error) {
	if !p.enforceScopeRLS {
		return query, args, nil
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return "", nil, err
	}

	maxPlaceholder := 0
	for _, match := range placeholderPattern.FindAllStringSubmatch(query, -1) {
		if len(match) != 2 {
			continue
		}
		value, convErr := strconv.Atoi(match[1])
		if convErr != nil {
			continue
		}
		if value > maxPlaceholder {
			maxPlaceholder = value
		}
	}

	tenantPos := maxPlaceholder + 1
	workspacePos := maxPlaceholder + 2
	enforcePos := maxPlaceholder + 3
	scopeCTE := fmt.Sprintf(
		"_identrail_scope AS (SELECT set_config('identrail.tenant_id', $%d, true), set_config('identrail.workspace_id', $%d, true), set_config('identrail.rls_enforce', $%d, true))",
		tenantPos,
		workspacePos,
		enforcePos,
	)
	trimmed := strings.TrimSpace(query)
	upper := strings.ToUpper(trimmed)
	if strings.HasPrefix(upper, "WITH RECURSIVE ") {
		trimmed = strings.TrimSpace(trimmed[len("WITH RECURSIVE "):])
		query = "WITH RECURSIVE " + scopeCTE + ", " + trimmed
	} else if strings.HasPrefix(upper, "WITH ") {
		trimmed = strings.TrimSpace(trimmed[5:])
		query = "WITH " + scopeCTE + ", " + trimmed
	} else {
		query = "WITH " + scopeCTE + " " + query
	}

	capacity, err := checkedSliceCapacity(len(args), 3)
	if err != nil {
		return "", nil, err
	}

	scopedArgs := make([]any, 0, capacity)
	scopedArgs = append(scopedArgs, args...)
	scopedArgs = append(scopedArgs, scope.TenantID, scope.WorkspaceID, "on")
	return query, scopedArgs, nil
}

func (p *PostgresStore) execContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	scopedQuery, scopedArgs, err := p.injectScopeCTE(ctx, query, args)
	if err != nil {
		return nil, err
	}
	return p.db.ExecContext(ctx, scopedQuery, scopedArgs...)
}

func (p *PostgresStore) queryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	scopedQuery, scopedArgs, err := p.injectScopeCTE(ctx, query, args)
	if err != nil {
		return nil, err
	}
	return p.db.QueryContext(ctx, scopedQuery, scopedArgs...)
}

func (p *PostgresStore) queryRowContext(ctx context.Context, query string, args ...any) rowScanner {
	scopedQuery, scopedArgs, err := p.injectScopeCTE(ctx, query, args)
	if err != nil {
		return errScanner{err: err}
	}
	return p.db.QueryRowContext(ctx, scopedQuery, scopedArgs...)
}

func (p *PostgresStore) beginTx(ctx context.Context) (*sql.Tx, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if !p.enforceScopeRLS {
		return tx, nil
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	if _, err := tx.ExecContext(
		ctx,
		`SELECT set_config('identrail.tenant_id', $1, true), set_config('identrail.workspace_id', $2, true), set_config('identrail.rls_enforce', $3, true)`,
		scope.TenantID,
		scope.WorkspaceID,
		"on",
	); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("set rls scope context: %w", err)
	}
	return tx, nil
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
	scope, err := RequireScope(ctx)
	if err != nil {
		return ScanRecord{}, err
	}
	row := p.queryRowContext(
		ctx,
		`WITH next_scan AS (
			SELECT id
			FROM scans
			WHERE tenant_id = $1
			  AND workspace_id = $2
			  AND provider = $3
			  AND status = 'queued'
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
		RETURNING s.id, s.tenant_id, s.workspace_id, s.provider, s.status, s.started_at, s.finished_at, s.asset_count, s.finding_count, COALESCE(s.error_message, '')`,
		scope.TenantID,
		scope.WorkspaceID,
		strings.TrimSpace(provider),
	)
	var record ScanRecord
	var finishedAt sql.NullTime
	if err := row.Scan(
		&record.ID,
		&record.TenantID,
		&record.WorkspaceID,
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
	scope, err := RequireScope(ctx)
	if err != nil {
		return 0, err
	}
	var count int
	if err := p.queryRowContext(
		ctx,
		`SELECT COUNT(*)
		 FROM scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND provider = $3
		   AND status = 'queued'`,
		scope.TenantID,
		scope.WorkspaceID,
		strings.TrimSpace(provider),
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("count queued scans: %w", err)
	}
	return count, nil
}

// GetScan returns one scan by id.
func (p *PostgresStore) GetScan(ctx context.Context, scanID string) (ScanRecord, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return ScanRecord{}, err
	}
	row := p.queryRowContext(
		ctx,
		`SELECT id, tenant_id, workspace_id, provider, status, started_at, finished_at, asset_count, finding_count, COALESCE(error_message, '')
		 FROM scans
		 WHERE id = $1
		   AND tenant_id = $2
		   AND workspace_id = $3`,
		scanID,
		scope.TenantID,
		scope.WorkspaceID,
	)
	record, err := scanScanRecord(row)
	if err != nil {
		if errorsIsNoRows(err) {
			return ScanRecord{}, ErrNotFound
		}
		return ScanRecord{}, fmt.Errorf("query scan: %w", err)
	}
	return record, nil
}

// CompleteScan updates scan completion metadata.
func (p *PostgresStore) CompleteScan(ctx context.Context, scanID string, status string, finishedAt time.Time, assetCount int, findingCount int, errorMessage string) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	result, err := p.execContext(
		ctx,
		`UPDATE scans
		 SET status=$2, finished_at=$3, asset_count=$4, finding_count=$5, error_message=$6
		 WHERE id=$1
		   AND tenant_id=$7
		   AND workspace_id=$8`,
		scanID,
		status,
		finishedAt.UTC(),
		assetCount,
		findingCount,
		nullableString(errorMessage),
		scope.TenantID,
		scope.WorkspaceID,
	)
	if err != nil {
		return fmt.Errorf("complete scan: %w", err)
	}
	if err := ensureRowsAffected(result); err != nil {
		return err
	}
	return nil
}

// UpsertArtifacts inserts raw and normalized artifacts idempotently for one scan.
func (p *PostgresStore) UpsertArtifacts(ctx context.Context, scanID string, artifacts ScanArtifacts) error {
	if err := p.ensureScanInScope(ctx, scanID); err != nil {
		return err
	}
	tx, err := p.beginTx(ctx)
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
	if err := p.ensureScanInScope(ctx, scanID); err != nil {
		return err
	}
	tx, err := p.beginTx(ctx)
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

// GetFindingTriageState returns triage workflow state for one finding id.
func (p *PostgresStore) GetFindingTriageState(ctx context.Context, findingID string) (FindingTriageState, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return FindingTriageState{}, err
	}
	row := p.queryRowContext(
		ctx,
		`SELECT finding_id, status, assignee, suppression_expires_at, updated_at, updated_by
		 FROM finding_triage_states
		 WHERE finding_id = $1
		   AND tenant_id = $2
		   AND workspace_id = $3`,
		strings.TrimSpace(findingID),
		scope.TenantID,
		scope.WorkspaceID,
	)
	var state FindingTriageState
	var suppressionExpiresAt sql.NullTime
	if err := row.Scan(
		&state.FindingID,
		&state.Status,
		&state.Assignee,
		&suppressionExpiresAt,
		&state.UpdatedAt,
		&state.UpdatedBy,
	); err != nil {
		if err == sql.ErrNoRows {
			return FindingTriageState{}, ErrNotFound
		}
		return FindingTriageState{}, fmt.Errorf("query finding triage state: %w", err)
	}
	if suppressionExpiresAt.Valid {
		value := suppressionExpiresAt.Time.UTC()
		state.SuppressionExpiresAt = &value
	}
	state.UpdatedAt = state.UpdatedAt.UTC()
	return state, nil
}

// ListFindingTriageStates returns triage states for provided finding ids.
func (p *PostgresStore) ListFindingTriageStates(ctx context.Context, findingIDs []string) ([]FindingTriageState, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	unique := make([]string, 0, len(findingIDs))
	seen := map[string]struct{}{}
	for _, findingID := range findingIDs {
		normalized := strings.TrimSpace(findingID)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		unique = append(unique, normalized)
	}
	if len(unique) == 0 {
		return []FindingTriageState{}, nil
	}

	placeholders := make([]string, len(unique))
	args := make([]any, 0, len(unique)+2)
	args = append(args, scope.TenantID, scope.WorkspaceID)
	for i, findingID := range unique {
		placeholders[i] = fmt.Sprintf("$%d", i+3)
		args = append(args, findingID)
	}
	query := fmt.Sprintf(
		`SELECT finding_id, status, assignee, suppression_expires_at, updated_at, updated_by
		 FROM finding_triage_states
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND finding_id IN (%s)`,
		strings.Join(placeholders, ", "),
	)
	rows, err := p.queryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query finding triage states: %w", err)
	}
	defer rows.Close()

	result := make([]FindingTriageState, 0, len(unique))
	for rows.Next() {
		var state FindingTriageState
		var suppressionExpiresAt sql.NullTime
		if err := rows.Scan(
			&state.FindingID,
			&state.Status,
			&state.Assignee,
			&suppressionExpiresAt,
			&state.UpdatedAt,
			&state.UpdatedBy,
		); err != nil {
			return nil, fmt.Errorf("scan finding triage state row: %w", err)
		}
		if suppressionExpiresAt.Valid {
			value := suppressionExpiresAt.Time.UTC()
			state.SuppressionExpiresAt = &value
		}
		state.UpdatedAt = state.UpdatedAt.UTC()
		result = append(result, state)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("finding triage state rows: %w", err)
	}
	return result, nil
}

// UpsertFindingTriageState creates or updates mutable triage metadata.
func (p *PostgresStore) UpsertFindingTriageState(ctx context.Context, state FindingTriageState) error {
	return p.upsertFindingTriageStateWithExecutor(ctx, p.db, state)
}

func (p *PostgresStore) upsertFindingTriageStateWithExecutor(ctx context.Context, executor sqlExecutor, state FindingTriageState) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	updatedAt := state.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}
	_, err = executor.ExecContext(
		ctx,
		`INSERT INTO finding_triage_states (tenant_id, workspace_id, finding_id, status, assignee, suppression_expires_at, updated_at, updated_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (tenant_id, workspace_id, finding_id)
		 DO UPDATE SET
		   status = EXCLUDED.status,
		   assignee = EXCLUDED.assignee,
		   suppression_expires_at = EXCLUDED.suppression_expires_at,
		   updated_at = EXCLUDED.updated_at,
		   updated_by = EXCLUDED.updated_by`,
		scope.TenantID,
		scope.WorkspaceID,
		strings.TrimSpace(state.FindingID),
		strings.TrimSpace(string(state.Status)),
		strings.TrimSpace(state.Assignee),
		state.SuppressionExpiresAt,
		updatedAt.UTC(),
		strings.TrimSpace(state.UpdatedBy),
	)
	if err != nil {
		return fmt.Errorf("upsert finding triage state: %w", err)
	}
	return nil
}

// AppendFindingTriageEvent records one immutable triage action.
func (p *PostgresStore) AppendFindingTriageEvent(ctx context.Context, event FindingTriageEvent) error {
	return p.appendFindingTriageEventWithExecutor(ctx, p.db, event)
}

func (p *PostgresStore) appendFindingTriageEventWithExecutor(ctx context.Context, executor sqlExecutor, event FindingTriageEvent) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	createdAt := event.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	eventID := strings.TrimSpace(event.ID)
	if eventID == "" {
		eventID = uuid.NewString()
	}
	_, err = executor.ExecContext(
		ctx,
		`INSERT INTO finding_triage_events (id, tenant_id, workspace_id, finding_id, action, from_status, to_status, assignee, suppression_expires_at, comment, actor, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		eventID,
		scope.TenantID,
		scope.WorkspaceID,
		strings.TrimSpace(event.FindingID),
		strings.TrimSpace(event.Action),
		strings.TrimSpace(string(event.FromStatus)),
		strings.TrimSpace(string(event.ToStatus)),
		strings.TrimSpace(event.Assignee),
		event.SuppressionExpiresAt,
		strings.TrimSpace(event.Comment),
		strings.TrimSpace(event.Actor),
		createdAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("insert finding triage event: %w", err)
	}
	return nil
}

// ApplyFindingTriageTransition persists state and audit history atomically.
func (p *PostgresStore) ApplyFindingTriageTransition(ctx context.Context, state FindingTriageState, event FindingTriageEvent) error {
	if strings.TrimSpace(state.FindingID) == "" || strings.TrimSpace(event.FindingID) == "" {
		return fmt.Errorf("finding id is required")
	}
	if strings.TrimSpace(state.FindingID) != strings.TrimSpace(event.FindingID) {
		return fmt.Errorf("finding id mismatch between state and event")
	}

	tx, err := p.beginTx(ctx)
	if err != nil {
		return fmt.Errorf("begin triage transition tx: %w", err)
	}
	if err := p.upsertFindingTriageStateWithExecutor(ctx, tx, state); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := p.appendFindingTriageEventWithExecutor(ctx, tx, event); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit triage transition tx: %w", err)
	}
	return nil
}

// ListFindingTriageEvents returns triage history newest-first for one finding id.
func (p *PostgresStore) ListFindingTriageEvents(ctx context.Context, findingID string, limit int) ([]FindingTriageEvent, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	const maxFindingTriageEventsLimit = 500
	if limit <= 0 {
		limit = 100
	} else if limit > maxFindingTriageEventsLimit {
		limit = maxFindingTriageEventsLimit
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT id, finding_id, action, from_status, to_status, assignee, suppression_expires_at, comment, actor, created_at
		 FROM finding_triage_events
		 WHERE finding_id = $1
		   AND tenant_id = $2
		   AND workspace_id = $3
		 ORDER BY created_at DESC
		 LIMIT $4`,
		strings.TrimSpace(findingID),
		scope.TenantID,
		scope.WorkspaceID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query finding triage events: %w", err)
	}
	defer rows.Close()

	result := []FindingTriageEvent{}
	for rows.Next() {
		var event FindingTriageEvent
		var suppressionExpiresAt sql.NullTime
		if err := rows.Scan(
			&event.ID,
			&event.FindingID,
			&event.Action,
			&event.FromStatus,
			&event.ToStatus,
			&event.Assignee,
			&suppressionExpiresAt,
			&event.Comment,
			&event.Actor,
			&event.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan finding triage event row: %w", err)
		}
		if suppressionExpiresAt.Valid {
			value := suppressionExpiresAt.Time.UTC()
			event.SuppressionExpiresAt = &value
		}
		event.CreatedAt = event.CreatedAt.UTC()
		result = append(result, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("finding triage event rows: %w", err)
	}
	return result, nil
}

// ListScans returns latest scans first.
func (p *PostgresStore) ListScans(ctx context.Context, limit int) ([]ScanRecord, error) {
	if limit <= 0 {
		limit = 20
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT id, tenant_id, workspace_id, provider, status, started_at, finished_at, asset_count, finding_count, COALESCE(error_message, '')
		 FROM scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		 ORDER BY started_at DESC
		 LIMIT $3`,
		scope.TenantID,
		scope.WorkspaceID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query scans: %w", err)
	}
	defer rows.Close()
	result := []ScanRecord{}
	for rows.Next() {
		record, scanErr := scanScanRecord(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan row: %w", scanErr)
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
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT f.scan_id, f.finding_id, f.type, f.severity, f.title, f.human_summary, f.path, f.evidence, COALESCE(f.remediation, ''), f.created_at
		 FROM findings f
		 JOIN scans s ON s.id = f.scan_id
		 WHERE s.tenant_id = $1
		   AND s.workspace_id = $2
		 ORDER BY f.created_at DESC
		 LIMIT $3`,
		scope.TenantID,
		scope.WorkspaceID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()
	return findingsFromSQLRows(rows)
}

// ListFindingsByScan returns latest findings first for one scan id.
func (p *PostgresStore) ListFindingsByScan(ctx context.Context, scanID string, limit int) ([]domain.Finding, error) {
	if limit <= 0 {
		limit = 100
	}
	if err := p.ensureScanInScope(ctx, scanID); err != nil {
		return nil, err
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT f.scan_id, f.finding_id, f.type, f.severity, f.title, f.human_summary, f.path, f.evidence, COALESCE(f.remediation, ''), f.created_at
		 FROM findings f
		 JOIN scans s ON s.id = f.scan_id
		 WHERE f.scan_id = $1
		   AND s.tenant_id = $2
		   AND s.workspace_id = $3
		 ORDER BY f.created_at DESC
		 LIMIT $4`,
		scanID,
		scope.TenantID,
		scope.WorkspaceID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query findings by scan: %w", err)
	}
	defer rows.Close()
	return findingsFromSQLRows(rows)
}

// UpsertAuthzEntityAttributes creates or updates trusted authorization attributes.
func (p *PostgresStore) UpsertAuthzEntityAttributes(ctx context.Context, attributes AuthzEntityAttributes) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	normalized, err := NormalizeAuthzEntityAttributesForWrite(attributes)
	if err != nil {
		return err
	}
	normalized.TenantID = scope.TenantID
	normalized.WorkspaceID = scope.WorkspaceID

	_, err = p.execContext(
		ctx,
		`INSERT INTO authz_entity_attributes (
			tenant_id, workspace_id, entity_kind, entity_type, entity_id, owner_team, env, risk_tier, classification, updated_at
		) VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''), $10)
		ON CONFLICT (tenant_id, workspace_id, entity_kind, entity_type, entity_id)
		DO UPDATE SET
			owner_team = EXCLUDED.owner_team,
			env = EXCLUDED.env,
			risk_tier = EXCLUDED.risk_tier,
			classification = EXCLUDED.classification,
			updated_at = EXCLUDED.updated_at`,
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.EntityKind,
		normalized.EntityType,
		normalized.EntityID,
		normalized.OwnerTeam,
		normalized.Environment,
		normalized.RiskTier,
		normalized.Classification,
		normalized.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("upsert authz entity attributes: %w", err)
	}
	return nil
}

// GetAuthzEntityAttributes returns trusted authorization attributes for one entity.
func (p *PostgresStore) GetAuthzEntityAttributes(ctx context.Context, entityKind string, entityType string, entityID string) (AuthzEntityAttributes, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return AuthzEntityAttributes{}, err
	}
	normalized, err := NormalizeAuthzEntityAttributesForWrite(AuthzEntityAttributes{
		EntityKind: entityKind,
		EntityType: entityType,
		EntityID:   entityID,
	})
	if err != nil {
		return AuthzEntityAttributes{}, err
	}

	row := p.queryRowContext(
		ctx,
		`SELECT tenant_id, workspace_id, entity_kind, entity_type, entity_id, COALESCE(owner_team, ''), COALESCE(env, ''), COALESCE(risk_tier, ''), COALESCE(classification, ''), updated_at
		 FROM authz_entity_attributes
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND entity_kind = $3
		   AND entity_type = $4
		   AND entity_id = $5`,
		scope.TenantID,
		scope.WorkspaceID,
		normalized.EntityKind,
		normalized.EntityType,
		normalized.EntityID,
	)
	record, err := scanAuthzEntityAttributes(row)
	if err != nil {
		if errorsIsNoRows(err) {
			return AuthzEntityAttributes{}, ErrNotFound
		}
		return AuthzEntityAttributes{}, fmt.Errorf("query authz entity attributes: %w", err)
	}
	return record, nil
}

// UpsertAuthzRelationship creates or updates one scoped ReBAC tuple.
func (p *PostgresStore) UpsertAuthzRelationship(ctx context.Context, relationship AuthzRelationship) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	normalized, err := NormalizeAuthzRelationshipForWrite(relationship)
	if err != nil {
		return err
	}
	normalized.TenantID = scope.TenantID
	normalized.WorkspaceID = scope.WorkspaceID

	_, err = p.execContext(
		ctx,
		`INSERT INTO authz_relationships (
			tenant_id, workspace_id, subject_type, subject_id, relation, object_type, object_id, source, expires_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (tenant_id, workspace_id, subject_type, subject_id, relation, object_type, object_id)
		DO UPDATE SET
			source = EXCLUDED.source,
			expires_at = EXCLUDED.expires_at,
			updated_at = EXCLUDED.updated_at`,
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.SubjectType,
		normalized.SubjectID,
		normalized.Relation,
		normalized.ObjectType,
		normalized.ObjectID,
		normalized.Source,
		normalized.ExpiresAt,
		normalized.CreatedAt,
		normalized.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("upsert authz relationship: %w", err)
	}
	return nil
}

// DeleteAuthzRelationship removes one scoped ReBAC tuple.
func (p *PostgresStore) DeleteAuthzRelationship(ctx context.Context, relationship AuthzRelationship) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	normalized, err := NormalizeAuthzRelationshipForWrite(relationship)
	if err != nil {
		return err
	}
	result, err := p.execContext(
		ctx,
		`DELETE FROM authz_relationships
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND subject_type = $3
		   AND subject_id = $4
		   AND relation = $5
		   AND object_type = $6
		   AND object_id = $7`,
		scope.TenantID,
		scope.WorkspaceID,
		normalized.SubjectType,
		normalized.SubjectID,
		normalized.Relation,
		normalized.ObjectType,
		normalized.ObjectID,
	)
	if err != nil {
		return fmt.Errorf("delete authz relationship: %w", err)
	}
	if err := ensureRowsAffected(result); err != nil {
		return err
	}
	return nil
}

// ListAuthzRelationships returns scoped ReBAC tuples using optional filters.
func (p *PostgresStore) ListAuthzRelationships(ctx context.Context, filter AuthzRelationshipFilter, limit int) ([]AuthzRelationship, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	subjectType := strings.ToLower(strings.TrimSpace(filter.SubjectType))
	subjectID := strings.TrimSpace(filter.SubjectID)
	relation := strings.ToLower(strings.TrimSpace(filter.Relation))
	if relation != "" {
		if _, ok := validAuthzRelationships[relation]; !ok {
			return nil, fmt.Errorf("invalid relation value")
		}
	}
	objectType := strings.ToLower(strings.TrimSpace(filter.ObjectType))
	objectID := strings.TrimSpace(filter.ObjectID)

	args := []any{scope.TenantID, scope.WorkspaceID}
	query := strings.Builder{}
	query.WriteString(`SELECT tenant_id, workspace_id, subject_type, subject_id, relation, object_type, object_id, source, expires_at, created_at, updated_at
		FROM authz_relationships
		WHERE tenant_id = $1
		  AND workspace_id = $2`)

	next := 3
	if subjectType != "" {
		query.WriteString(fmt.Sprintf(" AND subject_type = $%d", next))
		args = append(args, subjectType)
		next++
	}
	if subjectID != "" {
		query.WriteString(fmt.Sprintf(" AND subject_id = $%d", next))
		args = append(args, subjectID)
		next++
	}
	if relation != "" {
		query.WriteString(fmt.Sprintf(" AND relation = $%d", next))
		args = append(args, relation)
		next++
	}
	if objectType != "" {
		query.WriteString(fmt.Sprintf(" AND object_type = $%d", next))
		args = append(args, objectType)
		next++
	}
	if objectID != "" {
		query.WriteString(fmt.Sprintf(" AND object_id = $%d", next))
		args = append(args, objectID)
		next++
	}
	if !filter.IncludeExpired {
		query.WriteString(fmt.Sprintf(" AND (expires_at IS NULL OR expires_at > $%d)", next))
		args = append(args, time.Now().UTC())
		next++
	}
	query.WriteString(" ORDER BY subject_type ASC, subject_id ASC, relation ASC, object_type ASC, object_id ASC")
	if limit > 0 {
		query.WriteString(fmt.Sprintf(" LIMIT $%d", next))
		args = append(args, limit)
	}

	rows, err := p.queryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("query authz relationships: %w", err)
	}
	defer rows.Close()

	result := []AuthzRelationship{}
	for rows.Next() {
		record, scanErr := scanAuthzRelationship(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("authz relationship row: %w", scanErr)
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("authz relationship rows: %w", err)
	}
	return result, nil
}

// UpsertAuthzPolicySet creates or updates one scoped policy set metadata record.
func (p *PostgresStore) UpsertAuthzPolicySet(ctx context.Context, policySet AuthzPolicySet) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	normalized, err := NormalizeAuthzPolicySetForWrite(policySet)
	if err != nil {
		return err
	}
	normalized.TenantID = scope.TenantID
	normalized.WorkspaceID = scope.WorkspaceID

	_, err = p.execContext(
		ctx,
		`INSERT INTO authz_policy_sets (
			tenant_id, workspace_id, policy_set_id, display_name, description, created_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), $7, $8)
		ON CONFLICT (tenant_id, workspace_id, policy_set_id)
		DO UPDATE SET
			display_name = EXCLUDED.display_name,
			description = EXCLUDED.description,
			updated_at = EXCLUDED.updated_at`,
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.PolicySetID,
		normalized.DisplayName,
		normalized.Description,
		normalized.CreatedBy,
		normalized.CreatedAt,
		normalized.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("upsert authz policy set: %w", err)
	}
	return nil
}

// GetAuthzPolicySet returns one scoped policy set metadata record.
func (p *PostgresStore) GetAuthzPolicySet(ctx context.Context, policySetID string) (AuthzPolicySet, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return AuthzPolicySet{}, err
	}
	normalizedPolicySetID, err := normalizeAuthzPolicySetID(policySetID)
	if err != nil {
		return AuthzPolicySet{}, err
	}

	row := p.queryRowContext(
		ctx,
		`SELECT tenant_id, workspace_id, policy_set_id, display_name, COALESCE(description, ''), COALESCE(created_by, ''), created_at, updated_at
		 FROM authz_policy_sets
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND policy_set_id = $3`,
		scope.TenantID,
		scope.WorkspaceID,
		normalizedPolicySetID,
	)
	record, err := scanAuthzPolicySet(row)
	if err != nil {
		if errorsIsNoRows(err) {
			return AuthzPolicySet{}, ErrNotFound
		}
		return AuthzPolicySet{}, fmt.Errorf("query authz policy set: %w", err)
	}
	return record, nil
}

// CreateAuthzPolicyVersion persists one immutable policy bundle version.
func (p *PostgresStore) CreateAuthzPolicyVersion(ctx context.Context, version AuthzPolicyVersion) (AuthzPolicyVersion, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return AuthzPolicyVersion{}, err
	}
	normalizedPolicySetID, err := normalizeAuthzPolicySetID(version.PolicySetID)
	if err != nil {
		return AuthzPolicyVersion{}, err
	}
	if _, err := p.GetAuthzPolicySet(ctx, normalizedPolicySetID); err != nil {
		return AuthzPolicyVersion{}, err
	}
	autoIncrement := version.Version <= 0
	if autoIncrement {
		// Placeholder only for shared normalization; SQL computes final version.
		version.Version = 1
	}
	version.PolicySetID = normalizedPolicySetID

	normalized, err := NormalizeAuthzPolicyVersionForWrite(version)
	if err != nil {
		return AuthzPolicyVersion{}, err
	}
	normalized.TenantID = scope.TenantID
	normalized.WorkspaceID = scope.WorkspaceID

	if autoIncrement {
		const maxAutoVersionInsertRetries = 5
		for attempt := 0; attempt < maxAutoVersionInsertRetries; attempt++ {
			row := p.queryRowContext(
				ctx,
				`INSERT INTO authz_policy_versions (
					tenant_id, workspace_id, policy_set_id, version, bundle, checksum, created_by, created_at
				)
				SELECT
					$1,
					$2,
					$3,
					COALESCE(MAX(version), 0) + 1,
					$4::jsonb,
					$5,
					NULLIF($6, ''),
					$7
				FROM authz_policy_versions
				WHERE tenant_id = $1
				  AND workspace_id = $2
				  AND policy_set_id = $3
				ON CONFLICT (tenant_id, workspace_id, policy_set_id, version) DO NOTHING
				RETURNING tenant_id, workspace_id, policy_set_id, version, bundle::text, checksum, COALESCE(created_by, ''), created_at`,
				normalized.TenantID,
				normalized.WorkspaceID,
				normalized.PolicySetID,
				normalized.Bundle,
				normalized.Checksum,
				normalized.CreatedBy,
				normalized.CreatedAt,
			)
			record, scanErr := scanAuthzPolicyVersion(row)
			if scanErr == nil {
				return record, nil
			}
			if errorsIsNoRows(scanErr) {
				continue
			}
			return AuthzPolicyVersion{}, fmt.Errorf("insert authz policy version: %w", scanErr)
		}
		return AuthzPolicyVersion{}, fmt.Errorf("failed to allocate authz policy version after retries")
	}

	row := p.queryRowContext(
		ctx,
		`INSERT INTO authz_policy_versions (
			tenant_id, workspace_id, policy_set_id, version, bundle, checksum, created_by, created_at
		) VALUES ($1, $2, $3, $4, $5::jsonb, $6, NULLIF($7, ''), $8)
		RETURNING tenant_id, workspace_id, policy_set_id, version, bundle::text, checksum, COALESCE(created_by, ''), created_at`,
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.PolicySetID,
		normalized.Version,
		normalized.Bundle,
		normalized.Checksum,
		normalized.CreatedBy,
		normalized.CreatedAt,
	)
	record, err := scanAuthzPolicyVersion(row)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return AuthzPolicyVersion{}, fmt.Errorf("authz policy version already exists")
		}
		return AuthzPolicyVersion{}, fmt.Errorf("insert authz policy version: %w", err)
	}
	return record, nil
}

// GetAuthzPolicyVersion returns one immutable bundle version in scope.
func (p *PostgresStore) GetAuthzPolicyVersion(ctx context.Context, policySetID string, version int) (AuthzPolicyVersion, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return AuthzPolicyVersion{}, err
	}
	normalizedPolicySetID, err := normalizeAuthzPolicySetID(policySetID)
	if err != nil {
		return AuthzPolicyVersion{}, err
	}
	if version <= 0 {
		return AuthzPolicyVersion{}, fmt.Errorf("version must be greater than zero")
	}

	row := p.queryRowContext(
		ctx,
		`SELECT tenant_id, workspace_id, policy_set_id, version, bundle::text, checksum, COALESCE(created_by, ''), created_at
		 FROM authz_policy_versions
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND policy_set_id = $3
		   AND version = $4`,
		scope.TenantID,
		scope.WorkspaceID,
		normalizedPolicySetID,
		version,
	)
	record, err := scanAuthzPolicyVersion(row)
	if err != nil {
		if errorsIsNoRows(err) {
			return AuthzPolicyVersion{}, ErrNotFound
		}
		return AuthzPolicyVersion{}, fmt.Errorf("query authz policy version: %w", err)
	}
	return record, nil
}

// ListAuthzPolicyVersions returns policy versions for one policy set ordered by newest first.
func (p *PostgresStore) ListAuthzPolicyVersions(ctx context.Context, policySetID string, limit int) ([]AuthzPolicyVersion, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	normalizedPolicySetID, err := normalizeAuthzPolicySetID(policySetID)
	if err != nil {
		return nil, err
	}
	const maxPolicyVersionListLimit = 500
	if limit <= 0 {
		limit = 100
	} else if limit > maxPolicyVersionListLimit {
		limit = maxPolicyVersionListLimit
	}

	rows, err := p.queryContext(
		ctx,
		`SELECT tenant_id, workspace_id, policy_set_id, version, bundle::text, checksum, COALESCE(created_by, ''), created_at
		 FROM authz_policy_versions
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND policy_set_id = $3
		 ORDER BY version DESC
		 LIMIT $4`,
		scope.TenantID,
		scope.WorkspaceID,
		normalizedPolicySetID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query authz policy versions: %w", err)
	}
	defer rows.Close()

	result := []AuthzPolicyVersion{}
	for rows.Next() {
		record, scanErr := scanAuthzPolicyVersion(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("authz policy version row: %w", scanErr)
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("authz policy version rows: %w", err)
	}
	return result, nil
}

// UpsertAuthzPolicyRollout creates or updates one scoped rollout pointer row.
func (p *PostgresStore) UpsertAuthzPolicyRollout(ctx context.Context, rollout AuthzPolicyRollout) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	normalized, err := NormalizeAuthzPolicyRolloutForWrite(rollout)
	if err != nil {
		return err
	}
	normalized.TenantID = scope.TenantID
	normalized.WorkspaceID = scope.WorkspaceID
	tenantAllowlistPayload, err := json.Marshal(normalized.TenantAllowlist)
	if err != nil {
		return fmt.Errorf("marshal tenant allowlist: %w", err)
	}
	workspaceAllowlistPayload, err := json.Marshal(normalized.WorkspaceAllowlist)
	if err != nil {
		return fmt.Errorf("marshal workspace allowlist: %w", err)
	}
	validatedVersionsPayload, err := json.Marshal(normalized.ValidatedVersions)
	if err != nil {
		return fmt.Errorf("marshal validated versions: %w", err)
	}

	_, err = p.execContext(
		ctx,
		`INSERT INTO authz_policy_rollouts (
			tenant_id, workspace_id, policy_set_id, active_version, candidate_version, mode,
			tenant_allowlist, workspace_allowlist, canary_percentage, validated_versions, updated_by, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10::jsonb, NULLIF($11, ''), $12)
		ON CONFLICT (tenant_id, workspace_id, policy_set_id)
		DO UPDATE SET
			active_version = EXCLUDED.active_version,
			candidate_version = EXCLUDED.candidate_version,
			mode = EXCLUDED.mode,
			tenant_allowlist = EXCLUDED.tenant_allowlist,
			workspace_allowlist = EXCLUDED.workspace_allowlist,
			canary_percentage = EXCLUDED.canary_percentage,
			validated_versions = EXCLUDED.validated_versions,
			updated_by = EXCLUDED.updated_by,
			updated_at = EXCLUDED.updated_at`,
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.PolicySetID,
		normalized.ActiveVersion,
		normalized.CandidateVersion,
		normalized.Mode,
		tenantAllowlistPayload,
		workspaceAllowlistPayload,
		normalized.CanaryPercentage,
		validatedVersionsPayload,
		normalized.UpdatedBy,
		normalized.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("upsert authz policy rollout: %w", err)
	}
	return nil
}

// GetAuthzPolicyRollout returns one scoped rollout pointer row.
func (p *PostgresStore) GetAuthzPolicyRollout(ctx context.Context, policySetID string) (AuthzPolicyRollout, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return AuthzPolicyRollout{}, err
	}
	normalizedPolicySetID, err := normalizeAuthzPolicySetID(policySetID)
	if err != nil {
		return AuthzPolicyRollout{}, err
	}

	row := p.queryRowContext(
		ctx,
		`SELECT tenant_id, workspace_id, policy_set_id, active_version, candidate_version, mode,
			COALESCE(tenant_allowlist, '[]'::jsonb)::text,
			COALESCE(workspace_allowlist, '[]'::jsonb)::text,
			canary_percentage,
			COALESCE(validated_versions, '[]'::jsonb)::text,
			COALESCE(updated_by, ''), updated_at
		 FROM authz_policy_rollouts
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND policy_set_id = $3`,
		scope.TenantID,
		scope.WorkspaceID,
		normalizedPolicySetID,
	)
	record, err := scanAuthzPolicyRollout(row)
	if err != nil {
		if errorsIsNoRows(err) {
			return AuthzPolicyRollout{}, ErrNotFound
		}
		return AuthzPolicyRollout{}, fmt.Errorf("query authz policy rollout: %w", err)
	}
	return record, nil
}

// AppendAuthzPolicyEvent records one immutable policy lifecycle event.
func (p *PostgresStore) AppendAuthzPolicyEvent(ctx context.Context, event AuthzPolicyEvent) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	normalized, err := NormalizeAuthzPolicyEventForWrite(event)
	if err != nil {
		return err
	}
	normalized.TenantID = scope.TenantID
	normalized.WorkspaceID = scope.WorkspaceID
	if normalized.ID == "" {
		normalized.ID = uuid.NewString()
	}

	var metadataPayload any
	if normalized.Metadata != nil {
		payload, err := json.Marshal(normalized.Metadata)
		if err != nil {
			return fmt.Errorf("marshal authz policy event metadata: %w", err)
		}
		metadataPayload = payload
	}

	_, err = p.execContext(
		ctx,
		`INSERT INTO authz_policy_events (
			id, tenant_id, workspace_id, policy_set_id, event_type, from_version, to_version, actor, message, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), NULLIF($9, ''), $10::jsonb, $11)`,
		normalized.ID,
		normalized.TenantID,
		normalized.WorkspaceID,
		normalized.PolicySetID,
		normalized.EventType,
		normalized.FromVersion,
		normalized.ToVersion,
		normalized.Actor,
		normalized.Message,
		metadataPayload,
		normalized.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert authz policy event: %w", err)
	}
	return nil
}

// ListAuthzPolicyEvents returns lifecycle events for one policy set (newest first).
func (p *PostgresStore) ListAuthzPolicyEvents(ctx context.Context, policySetID string, limit int) ([]AuthzPolicyEvent, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	normalizedPolicySetID, err := normalizeAuthzPolicySetID(policySetID)
	if err != nil {
		return nil, err
	}
	const maxPolicyEventListLimit = 500
	if limit <= 0 {
		limit = 100
	} else if limit > maxPolicyEventListLimit {
		limit = maxPolicyEventListLimit
	}

	rows, err := p.queryContext(
		ctx,
		`SELECT id, tenant_id, workspace_id, policy_set_id, event_type, from_version, to_version, COALESCE(actor, ''), COALESCE(message, ''), COALESCE(metadata, '{}'::jsonb), created_at
		 FROM authz_policy_events
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND policy_set_id = $3
		 ORDER BY created_at DESC
		 LIMIT $4`,
		scope.TenantID,
		scope.WorkspaceID,
		normalizedPolicySetID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query authz policy events: %w", err)
	}
	defer rows.Close()

	result := []AuthzPolicyEvent{}
	for rows.Next() {
		record, scanErr := scanAuthzPolicyEvent(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("authz policy event row: %w", scanErr)
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("authz policy event rows: %w", err)
	}
	return result, nil
}

// ListIdentities returns identities filtered by scan/provider/type/name prefix.
func (p *PostgresStore) ListIdentities(ctx context.Context, filter IdentityFilter, limit int) ([]domain.Identity, error) {
	if limit <= 0 {
		limit = 100
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(filter.ScanID) != "" {
		if err := p.ensureScanInScope(ctx, filter.ScanID); err != nil {
			return nil, err
		}
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT i.id, i.provider, i.type, i.name, COALESCE(i.arn, ''), COALESCE(i.owner_hint, ''), i.created_at, i.last_used_at, i.tags, i.raw_ref
		 FROM identities i
		 JOIN scans s ON s.id = i.scan_id
		 WHERE ($1 = '' OR i.scan_id = $1::uuid)
		   AND ($2 = '' OR i.provider = $2)
		   AND ($3 = '' OR i.type = $3)
		   AND ($4 = '' OR LOWER(i.name) LIKE LOWER($4 || '%'))
		   AND s.tenant_id = $6
		   AND s.workspace_id = $7
		 ORDER BY i.name ASC
		 LIMIT $5`,
		filter.ScanID,
		filter.Provider,
		filter.Type,
		filter.NamePrefix,
		limit,
		scope.TenantID,
		scope.WorkspaceID,
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
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(filter.ScanID) != "" {
		if err := p.ensureScanInScope(ctx, filter.ScanID); err != nil {
			return nil, err
		}
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT r.id, r.type, r.from_node_id, r.to_node_id, COALESCE(r.evidence_ref, ''), r.discovered_at
		 FROM relationships r
		 JOIN scans s ON s.id = r.scan_id
		 WHERE ($1 = '' OR r.scan_id = $1::uuid)
		   AND ($2 = '' OR r.type = $2)
		   AND ($3 = '' OR r.from_node_id = $3)
		   AND ($4 = '' OR r.to_node_id = $4)
		   AND s.tenant_id = $6
		   AND s.workspace_id = $7
		 ORDER BY r.discovered_at DESC
		 LIMIT $5`,
		filter.ScanID,
		filter.Type,
		filter.FromNodeID,
		filter.ToNodeID,
		limit,
		scope.TenantID,
		scope.WorkspaceID,
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
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	normalizedLevel, levelErr := NormalizeScanEventLevel(strings.ToLower(strings.TrimSpace(level)))
	if levelErr != nil {
		return levelErr
	}
	payload, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("marshal scan event metadata: %w", err)
	}
	result, err := p.execContext(
		ctx,
		`INSERT INTO scan_events (id, scan_id, level, message, metadata, created_at)
		 SELECT $1, $2, $3, $4, $5, NOW()
		 FROM scans s
		 WHERE s.id = $2
		   AND s.tenant_id = $6
		   AND s.workspace_id = $7`,
		uuid.NewString(),
		scanID,
		normalizedLevel,
		message,
		payload,
		scope.TenantID,
		scope.WorkspaceID,
	)
	if err != nil {
		return fmt.Errorf("insert scan event: %w", err)
	}
	if err := ensureRowsAffected(result); err != nil {
		return err
	}
	return nil
}

// ListScanEvents returns latest event entries for one scan.
func (p *PostgresStore) ListScanEvents(ctx context.Context, scanID string, limit int) ([]ScanEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	if err := p.ensureScanInScope(ctx, scanID); err != nil {
		return nil, err
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT e.id, e.scan_id, e.level, e.message, e.metadata, e.created_at
		 FROM scan_events e
		 JOIN scans s ON s.id = e.scan_id
		 WHERE e.scan_id = $1
		   AND s.tenant_id = $2
		   AND s.workspace_id = $3
		 ORDER BY e.created_at DESC
		 LIMIT $4`,
		scanID,
		scope.TenantID,
		scope.WorkspaceID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query scan events: %w", err)
	}
	defer rows.Close()
	result := []ScanEvent{}
	for rows.Next() {
		var row ScanEvent
		var metadata []byte
		if err := rows.Scan(&row.ID, &row.ScanID, &row.Level, &row.Message, &metadata, &row.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan event row: %w", err)
		}
		event := ScanEvent{
			ID:        row.ID,
			ScanID:    row.ScanID,
			Level:     row.Level,
			Message:   row.Message,
			CreatedAt: row.CreatedAt,
		}
		if len(metadata) > 0 {
			if err := json.Unmarshal(metadata, &event.Metadata); err != nil {
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
	scope, err := RequireScope(ctx)
	if err != nil {
		return RepoScanRecord{}, err
	}
	row := p.queryRowContext(
		ctx,
		`WITH next_repo_scan AS (
			SELECT id
			FROM repo_scans
			WHERE tenant_id = $1
			  AND workspace_id = $2
			  AND status = 'queued'
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
			r.tenant_id,
			r.workspace_id,
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
		scope.TenantID,
		scope.WorkspaceID,
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
	scope, err := RequireScope(ctx)
	if err != nil {
		return 0, err
	}
	var count int
	if err := p.queryRowContext(
		ctx,
		`SELECT COUNT(*)
		 FROM repo_scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND status = 'queued'`,
		scope.TenantID,
		scope.WorkspaceID,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("count queued repo scans: %w", err)
	}
	return count, nil
}

// CountPendingRepoScansByRepository returns queued+running scan count for one repository.
func (p *PostgresStore) CountPendingRepoScansByRepository(ctx context.Context, repository string) (int, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return 0, err
	}
	var count int
	if err := p.queryRowContext(
		ctx,
		`SELECT COUNT(*)
		 FROM repo_scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND LOWER(repository) = LOWER($3)
		   AND status IN ('queued', 'running')`,
		scope.TenantID,
		scope.WorkspaceID,
		strings.TrimSpace(repository),
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("count pending repo scans: %w", err)
	}
	return count, nil
}

// RequeueRepoScan moves one running repository scan back to queued.
func (p *PostgresStore) RequeueRepoScan(ctx context.Context, repoScanID string) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	result, err := p.execContext(
		ctx,
		`UPDATE repo_scans
		 SET status = 'queued',
		     started_at = NOW(),
		     finished_at = NULL,
		     error_message = NULL
		 WHERE id = $1
		   AND tenant_id = $2
		   AND workspace_id = $3
		   AND status = 'running'`,
		repoScanID,
		scope.TenantID,
		scope.WorkspaceID,
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
	scope, err := RequireScope(ctx)
	if err != nil {
		return RepoScanRecord{}, err
	}
	record := RepoScanRecord{
		ID:           uuid.NewString(),
		TenantID:     scope.TenantID,
		WorkspaceID:  scope.WorkspaceID,
		Repository:   strings.TrimSpace(repository),
		Status:       strings.TrimSpace(status),
		StartedAt:    startedAt.UTC(),
		HistoryLimit: historyLimit,
		MaxFindings:  maxFindings,
	}
	_, err = p.execContext(
		ctx,
		`INSERT INTO repo_scans (id, tenant_id, workspace_id, repository, status, started_at, commits_scanned, files_scanned, finding_count, truncated, history_limit, max_findings_limit)
		 VALUES ($1, $2, $3, $4, $5, $6, 0, 0, 0, false, $7, $8)`,
		record.ID,
		record.TenantID,
		record.WorkspaceID,
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
	scope, err := RequireScope(ctx)
	if err != nil {
		return RepoScanRecord{}, err
	}
	row := p.queryRowContext(
		ctx,
		`SELECT id, tenant_id, workspace_id, repository, status, started_at, finished_at, commits_scanned, files_scanned, finding_count, truncated, COALESCE(error_message, ''), history_limit, max_findings_limit
		 FROM repo_scans
		 WHERE id = $1
		   AND tenant_id = $2
		   AND workspace_id = $3`,
		repoScanID,
		scope.TenantID,
		scope.WorkspaceID,
	)
	record, err := scanRepoScanRecord(row)
	if err != nil {
		if errorsIsNoRows(err) {
			return RepoScanRecord{}, ErrNotFound
		}
		return RepoScanRecord{}, fmt.Errorf("query repo scan: %w", err)
	}
	return record, nil
}

// CompleteRepoScan updates repository scan completion metadata.
func (p *PostgresStore) CompleteRepoScan(ctx context.Context, repoScanID string, status string, finishedAt time.Time, commitsScanned int, filesScanned int, findingCount int, truncated bool, errorMessage string) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	result, err := p.execContext(
		ctx,
		`UPDATE repo_scans
		 SET status = $2,
		     finished_at = $3,
		     commits_scanned = $4,
		     files_scanned = $5,
		     finding_count = $6,
		     truncated = $7,
		     error_message = $8
		 WHERE id = $1
		   AND tenant_id = $9
		   AND workspace_id = $10`,
		repoScanID,
		strings.TrimSpace(status),
		finishedAt.UTC(),
		commitsScanned,
		filesScanned,
		findingCount,
		truncated,
		nullableString(errorMessage),
		scope.TenantID,
		scope.WorkspaceID,
	)
	if err != nil {
		return fmt.Errorf("complete repo scan: %w", err)
	}
	if err := ensureRowsAffected(result); err != nil {
		return err
	}
	return nil
}

// UpsertRepoFindings inserts repository findings idempotently.
func (p *PostgresStore) UpsertRepoFindings(ctx context.Context, repoScanID string, findings []domain.Finding) error {
	if err := p.ensureRepoScanInScope(ctx, repoScanID); err != nil {
		return err
	}
	tx, err := p.beginTx(ctx)
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
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT id, tenant_id, workspace_id, repository, status, started_at, finished_at, commits_scanned, files_scanned, finding_count, truncated, COALESCE(error_message, ''), history_limit, max_findings_limit
		 FROM repo_scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		 ORDER BY started_at DESC
		 LIMIT $3`,
		scope.TenantID,
		scope.WorkspaceID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query repo scans: %w", err)
	}
	defer rows.Close()
	result := []RepoScanRecord{}
	for rows.Next() {
		record, scanErr := scanRepoScanRecord(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("repo scan row: %w", scanErr)
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("repo scan rows: %w", err)
	}
	return result, nil
}

// ListRepoFindings returns latest repository findings first with optional filters.
func (p *PostgresStore) ListRepoFindings(ctx context.Context, filter RepoFindingFilter, limit int) ([]domain.Finding, error) {
	if limit <= 0 {
		limit = 100
	}
	repoScanID := strings.TrimSpace(filter.RepoScanID)
	if repoScanID != "" {
		if err := p.ensureRepoScanInScope(ctx, repoScanID); err != nil {
			return nil, err
		}
	}
	scope, err := RequireScope(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := p.queryContext(
		ctx,
		`SELECT rf.repo_scan_id, rf.finding_id, rf.type, rf.severity, rf.title, rf.human_summary, rf.path, rf.evidence, COALESCE(rf.remediation, ''), rf.created_at
		 FROM repo_findings rf
		 JOIN repo_scans rs ON rs.id = rf.repo_scan_id
		 WHERE ($1 = '' OR rf.repo_scan_id = $1::uuid)
		   AND ($2 = '' OR rf.severity = $2)
		   AND ($3 = '' OR rf.type = $3)
		   AND rs.tenant_id = $5
		   AND rs.workspace_id = $6
		 ORDER BY rf.created_at DESC
		 LIMIT $4`,
		repoScanID,
		strings.TrimSpace(filter.Severity),
		strings.TrimSpace(filter.Type),
		limit,
		scope.TenantID,
		scope.WorkspaceID,
	)
	if err != nil {
		return nil, fmt.Errorf("query repo findings: %w", err)
	}
	defer rows.Close()
	result := []domain.Finding{}
	for rows.Next() {
		var row struct {
			RepoScanID   string
			FindingID    string
			Type         string
			Severity     string
			Title        string
			HumanSummary string
			Path         []byte
			Evidence     []byte
			Remediation  string
			CreatedAt    time.Time
		}
		if err := rows.Scan(
			&row.RepoScanID,
			&row.FindingID,
			&row.Type,
			&row.Severity,
			&row.Title,
			&row.HumanSummary,
			&row.Path,
			&row.Evidence,
			&row.Remediation,
			&row.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("repo finding row: %w", err)
		}
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
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("repo finding rows: %w", err)
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

func (p *PostgresStore) createScanWithStatus(ctx context.Context, provider string, status string, startedAt time.Time) (ScanRecord, error) {
	scope, err := RequireScope(ctx)
	if err != nil {
		return ScanRecord{}, err
	}
	record := ScanRecord{
		ID:          uuid.NewString(),
		TenantID:    scope.TenantID,
		WorkspaceID: scope.WorkspaceID,
		Provider:    strings.TrimSpace(provider),
		Status:      strings.TrimSpace(status),
		StartedAt:   startedAt.UTC(),
	}
	_, err = p.execContext(
		ctx,
		`INSERT INTO scans (id, tenant_id, workspace_id, provider, status, started_at, asset_count, finding_count) VALUES ($1, $2, $3, $4, $5, $6, 0, 0)`,
		record.ID,
		record.TenantID,
		record.WorkspaceID,
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
		&record.TenantID,
		&record.WorkspaceID,
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

func scanScanRecord(scanner scanner) (ScanRecord, error) {
	var record ScanRecord
	var finishedAt sql.NullTime
	if err := scanner.Scan(
		&record.ID,
		&record.TenantID,
		&record.WorkspaceID,
		&record.Provider,
		&record.Status,
		&record.StartedAt,
		&finishedAt,
		&record.AssetCount,
		&record.FindingCount,
		&record.ErrorMessage,
	); err != nil {
		return ScanRecord{}, err
	}
	record.StartedAt = record.StartedAt.UTC()
	if finishedAt.Valid {
		finished := finishedAt.Time.UTC()
		record.FinishedAt = &finished
	}
	return record, nil
}

func scanAuthzEntityAttributes(scanner scanner) (AuthzEntityAttributes, error) {
	var record AuthzEntityAttributes
	if err := scanner.Scan(
		&record.TenantID,
		&record.WorkspaceID,
		&record.EntityKind,
		&record.EntityType,
		&record.EntityID,
		&record.OwnerTeam,
		&record.Environment,
		&record.RiskTier,
		&record.Classification,
		&record.UpdatedAt,
	); err != nil {
		return AuthzEntityAttributes{}, err
	}
	record.UpdatedAt = record.UpdatedAt.UTC()
	return record, nil
}

func scanAuthzRelationship(scanner scanner) (AuthzRelationship, error) {
	var record AuthzRelationship
	var expiresAt sql.NullTime
	if err := scanner.Scan(
		&record.TenantID,
		&record.WorkspaceID,
		&record.SubjectType,
		&record.SubjectID,
		&record.Relation,
		&record.ObjectType,
		&record.ObjectID,
		&record.Source,
		&expiresAt,
		&record.CreatedAt,
		&record.UpdatedAt,
	); err != nil {
		return AuthzRelationship{}, err
	}
	if expiresAt.Valid {
		converted := expiresAt.Time.UTC()
		record.ExpiresAt = &converted
	}
	record.CreatedAt = record.CreatedAt.UTC()
	record.UpdatedAt = record.UpdatedAt.UTC()
	return record, nil
}

func scanAuthzPolicySet(scanner scanner) (AuthzPolicySet, error) {
	var record AuthzPolicySet
	if err := scanner.Scan(
		&record.TenantID,
		&record.WorkspaceID,
		&record.PolicySetID,
		&record.DisplayName,
		&record.Description,
		&record.CreatedBy,
		&record.CreatedAt,
		&record.UpdatedAt,
	); err != nil {
		return AuthzPolicySet{}, err
	}
	record.CreatedAt = record.CreatedAt.UTC()
	record.UpdatedAt = record.UpdatedAt.UTC()
	return record, nil
}

func scanAuthzPolicyVersion(scanner scanner) (AuthzPolicyVersion, error) {
	var record AuthzPolicyVersion
	var bundle string
	if err := scanner.Scan(
		&record.TenantID,
		&record.WorkspaceID,
		&record.PolicySetID,
		&record.Version,
		&bundle,
		&record.Checksum,
		&record.CreatedBy,
		&record.CreatedAt,
	); err != nil {
		return AuthzPolicyVersion{}, err
	}
	record.Bundle = strings.TrimSpace(bundle)
	record.CreatedAt = record.CreatedAt.UTC()
	return record, nil
}

func scanAuthzPolicyRollout(scanner scanner) (AuthzPolicyRollout, error) {
	var record AuthzPolicyRollout
	var activeVersion sql.NullInt64
	var candidateVersion sql.NullInt64
	var tenantAllowlistJSON string
	var workspaceAllowlistJSON string
	var validatedVersionsJSON string
	if err := scanner.Scan(
		&record.TenantID,
		&record.WorkspaceID,
		&record.PolicySetID,
		&activeVersion,
		&candidateVersion,
		&record.Mode,
		&tenantAllowlistJSON,
		&workspaceAllowlistJSON,
		&record.CanaryPercentage,
		&validatedVersionsJSON,
		&record.UpdatedBy,
		&record.UpdatedAt,
	); err != nil {
		return AuthzPolicyRollout{}, err
	}
	if activeVersion.Valid {
		value := int(activeVersion.Int64)
		record.ActiveVersion = &value
	}
	if candidateVersion.Valid {
		value := int(candidateVersion.Int64)
		record.CandidateVersion = &value
	}
	if strings.TrimSpace(tenantAllowlistJSON) != "" {
		if err := json.Unmarshal([]byte(tenantAllowlistJSON), &record.TenantAllowlist); err != nil {
			return AuthzPolicyRollout{}, fmt.Errorf("decode tenant allowlist: %w", err)
		}
	}
	if strings.TrimSpace(workspaceAllowlistJSON) != "" {
		if err := json.Unmarshal([]byte(workspaceAllowlistJSON), &record.WorkspaceAllowlist); err != nil {
			return AuthzPolicyRollout{}, fmt.Errorf("decode workspace allowlist: %w", err)
		}
	}
	if strings.TrimSpace(validatedVersionsJSON) != "" {
		if err := json.Unmarshal([]byte(validatedVersionsJSON), &record.ValidatedVersions); err != nil {
			return AuthzPolicyRollout{}, fmt.Errorf("decode validated versions: %w", err)
		}
	}
	record.UpdatedAt = record.UpdatedAt.UTC()
	return record, nil
}

func scanAuthzPolicyEvent(scanner scanner) (AuthzPolicyEvent, error) {
	var record AuthzPolicyEvent
	var fromVersion sql.NullInt64
	var toVersion sql.NullInt64
	var metadata []byte
	if err := scanner.Scan(
		&record.ID,
		&record.TenantID,
		&record.WorkspaceID,
		&record.PolicySetID,
		&record.EventType,
		&fromVersion,
		&toVersion,
		&record.Actor,
		&record.Message,
		&metadata,
		&record.CreatedAt,
	); err != nil {
		return AuthzPolicyEvent{}, err
	}
	if fromVersion.Valid {
		value := int(fromVersion.Int64)
		record.FromVersion = &value
	}
	if toVersion.Valid {
		value := int(toVersion.Int64)
		record.ToVersion = &value
	}
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &record.Metadata); err != nil {
			return AuthzPolicyEvent{}, fmt.Errorf("decode authz policy event metadata: %w", err)
		}
	}
	record.CreatedAt = record.CreatedAt.UTC()
	return record, nil
}

func findingsFromSQLRows(rows *sql.Rows) ([]domain.Finding, error) {
	result := []domain.Finding{}
	for rows.Next() {
		var row struct {
			ScanID       string
			FindingID    string
			Type         string
			Severity     string
			Title        string
			HumanSummary string
			Path         []byte
			Evidence     []byte
			Remediation  string
			CreatedAt    time.Time
		}
		if err := rows.Scan(
			&row.ScanID,
			&row.FindingID,
			&row.Type,
			&row.Severity,
			&row.Title,
			&row.HumanSummary,
			&row.Path,
			&row.Evidence,
			&row.Remediation,
			&row.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("finding row: %w", err)
		}
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
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("finding rows: %w", err)
	}
	return result, nil
}

func ensureRowsAffected(result sql.Result) error {
	if result == nil {
		return ErrNotFound
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *PostgresStore) ensureScanInScope(ctx context.Context, scanID string) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	var exists bool
	err = p.queryRowContext(
		ctx,
		`SELECT EXISTS (
			SELECT 1
			FROM scans
			WHERE id = $1
			  AND tenant_id = $2
			  AND workspace_id = $3
		)`,
		scanID,
		scope.TenantID,
		scope.WorkspaceID,
	).Scan(&exists)
	if err != nil {
		return fmt.Errorf("verify scan scope: %w", err)
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func (p *PostgresStore) ensureRepoScanInScope(ctx context.Context, repoScanID string) error {
	scope, err := RequireScope(ctx)
	if err != nil {
		return err
	}
	var exists bool
	err = p.queryRowContext(
		ctx,
		`SELECT EXISTS (
			SELECT 1
			FROM repo_scans
			WHERE id = $1
			  AND tenant_id = $2
			  AND workspace_id = $3
		)`,
		repoScanID,
		scope.TenantID,
		scope.WorkspaceID,
	).Scan(&exists)
	if err != nil {
		return fmt.Errorf("verify repo scan scope: %w", err)
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func errorsIsNoRows(err error) bool {
	return err == sql.ErrNoRows
}
