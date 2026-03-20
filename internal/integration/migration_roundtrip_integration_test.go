//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/api"
	"github.com/Oluwatobi-Mustapha/identrail/internal/app"
	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

type roundtripScanner struct{}

func (roundtripScanner) Run(context.Context) (app.ScanResult, error) {
	now := time.Now().UTC()
	return app.ScanResult{
		Assets: 1,
		Bundle: providers.NormalizedBundle{},
		Findings: []domain.Finding{
			{
				ID:        "roundtrip-finding",
				Type:      domain.FindingOwnerless,
				Severity:  domain.SeverityHigh,
				Title:     "Ownerless identity",
				CreatedAt: now,
			},
		},
		Completed: now,
	}, nil
}

func TestPostgresIntegrationMigrationRoundTrip(t *testing.T) {
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
		t.Fatalf("apply up migrations: %v", err)
	}
	if err := store.ApplyDownMigrations(context.Background(), migrationsDir); err != nil {
		t.Fatalf("apply down migrations: %v", err)
	}
	if err := store.ApplyMigrations(context.Background(), migrationsDir); err != nil {
		t.Fatalf("re-apply up migrations: %v", err)
	}

	provider := "aws-roundtrip-" + time.Now().UTC().Format("150405")
	svc := api.NewService(store, roundtripScanner{}, provider)
	result, err := svc.RunScan(context.Background())
	if err != nil {
		t.Fatalf("run scan after migration roundtrip: %v", err)
	}
	if result.Scan.ID == "" || result.FindingCount != 1 {
		t.Fatalf("unexpected scan result after migration roundtrip: %+v", result)
	}
}
