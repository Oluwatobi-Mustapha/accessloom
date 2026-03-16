package db

import (
	"context"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
)

func TestMemoryStoreScanLifecycleAndFindings(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	scan, err := store.CreateScan(context.Background(), "aws", now)
	if err != nil {
		t.Fatalf("create scan failed: %v", err)
	}

	findings := []domain.Finding{{
		ID:           "finding-1",
		Type:         domain.FindingRiskyTrustPolicy,
		Severity:     domain.SeverityHigh,
		Title:        "Risky trust policy",
		HumanSummary: "Cross-account trust",
		CreatedAt:    now,
	}}
	if err := store.UpsertFindings(context.Background(), scan.ID, findings); err != nil {
		t.Fatalf("upsert findings failed: %v", err)
	}

	if err := store.CompleteScan(context.Background(), scan.ID, "completed", now.Add(2*time.Second), 3, 1, ""); err != nil {
		t.Fatalf("complete scan failed: %v", err)
	}

	scans, err := store.ListScans(context.Background(), 10)
	if err != nil {
		t.Fatalf("list scans failed: %v", err)
	}
	if len(scans) != 1 || scans[0].Status != "completed" || scans[0].FindingCount != 1 {
		t.Fatalf("unexpected scans: %+v", scans)
	}

	storedFindings, err := store.ListFindings(context.Background(), 10)
	if err != nil {
		t.Fatalf("list findings failed: %v", err)
	}
	if len(storedFindings) != 1 || storedFindings[0].ScanID != scan.ID {
		t.Fatalf("unexpected findings: %+v", storedFindings)
	}
}

func TestMemoryStoreErrorsForUnknownScan(t *testing.T) {
	store := NewMemoryStore()
	err := store.CompleteScan(context.Background(), "missing", "failed", time.Now(), 0, 0, "boom")
	if err == nil {
		t.Fatal("expected error")
	}

	err = store.UpsertFindings(context.Background(), "missing", []domain.Finding{{ID: "f1"}})
	if err == nil {
		t.Fatal("expected error")
	}
}
