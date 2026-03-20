//go:build integration

package integration

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/api"
	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestMigrationCompatibilityWithExistingRows(t *testing.T) {
	databaseURL := os.Getenv("IDENTRAIL_INTEGRATION_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set IDENTRAIL_INTEGRATION_DATABASE_URL to run integration tests")
	}

	store, err := db.NewPostgresStore(databaseURL)
	if err != nil {
		t.Fatalf("new postgres store: %v", err)
	}
	defer func() { _ = store.Close() }()

	migrationsDir := filepath.Clean(filepath.Join("..", "..", "migrations"))
	if err := store.ApplyMigrations(context.Background(), migrationsDir); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	sqlDB, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	defer func() { _ = sqlDB.Close() }()

	scanID := uuid.NewString()
	now := time.Now().UTC()
	provider := "aws-legacy-" + now.Format("150405")

	if _, err := sqlDB.ExecContext(
		context.Background(),
		`INSERT INTO scans (id, provider, status, started_at, finished_at, asset_count, finding_count, error_message)
		 VALUES ($1, $2, 'succeeded', $3, $4, 0, 1, NULL)`,
		scanID,
		provider,
		now.Add(-1*time.Minute),
		now,
	); err != nil {
		t.Fatalf("insert legacy scan row: %v", err)
	}

	if _, err := sqlDB.ExecContext(
		context.Background(),
		`INSERT INTO findings (scan_id, finding_id, type, severity, title, human_summary, path, evidence, remediation, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL, NULL, $7)`,
		scanID,
		"legacy-finding",
		"risky_trust_policy",
		"high",
		"Legacy risky trust",
		"Legacy persisted row with nullable fields.",
		now,
	); err != nil {
		t.Fatalf("insert legacy finding row: %v", err)
	}

	svc := api.NewService(store, integrationScanner{}, provider)

	scans, err := svc.ListScans(context.Background(), 20)
	if err != nil {
		t.Fatalf("list scans: %v", err)
	}
	foundScan := false
	for _, scan := range scans {
		if scan.ID == scanID {
			foundScan = true
			break
		}
	}
	if !foundScan {
		t.Fatalf("expected legacy scan %s in list", scanID)
	}

	findings, err := svc.ListFindingsFiltered(context.Background(), 20, api.FindingsFilter{
		ScanID: scanID,
	})
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "legacy-finding" {
		t.Fatalf("unexpected findings from legacy row: %+v", findings)
	}

	exports, err := svc.GetFindingExports(context.Background(), "legacy-finding", scanID)
	if err != nil {
		t.Fatalf("get exports for legacy finding: %v", err)
	}
	if len(exports.OCSF) == 0 || len(exports.ASFF) == 0 {
		t.Fatalf("expected populated exports for legacy finding, got %+v", exports)
	}
}
