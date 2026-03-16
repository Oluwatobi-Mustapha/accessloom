package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/app"
	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
)

type fakeScanner struct {
	result app.ScanResult
	err    error
}

func (f fakeScanner) Run(context.Context) (app.ScanResult, error) {
	if f.err != nil {
		return app.ScanResult{}, f.err
	}
	return f.result, nil
}

func TestServiceRunScanSuccess(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	svc := NewService(store, fakeScanner{result: app.ScanResult{
		Assets: 1,
		Findings: []domain.Finding{{
			ID:           "f1",
			Type:         domain.FindingRiskyTrustPolicy,
			Severity:     domain.SeverityHigh,
			Title:        "Risky",
			HumanSummary: "summary",
			CreatedAt:    now,
		}},
	}}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.RunScan(context.Background())
	if err != nil {
		t.Fatalf("run scan failed: %v", err)
	}
	if result.Scan.Status != "completed" || result.FindingCount != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestServiceRunScanFailure(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	svc := NewService(store, fakeScanner{err: errors.New("scanner failed")}, "aws")
	svc.Now = func() time.Time { return now }

	_, err := svc.RunScan(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}

	scans, listErr := store.ListScans(context.Background(), 1)
	if listErr != nil {
		t.Fatalf("list scans failed: %v", listErr)
	}
	if len(scans) != 1 || scans[0].Status != "failed" {
		t.Fatalf("expected failed scan record, got %+v", scans)
	}
}
