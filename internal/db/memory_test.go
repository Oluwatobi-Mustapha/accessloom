package db

import (
	"context"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
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
	if err := store.UpsertArtifacts(context.Background(), scan.ID, ScanArtifacts{
		RawAssets: []providers.RawAsset{{Kind: "iam_role", SourceID: "arn:aws:iam::1:role/test", Payload: []byte(`{"arn":"arn:aws:iam::1:role/test"}`), Collected: now.Format(time.RFC3339Nano)}},
		Bundle: providers.NormalizedBundle{
			Identities: []domain.Identity{{ID: "aws:identity:arn:aws:iam::1:role/test", Provider: domain.ProviderAWS, Type: domain.IdentityTypeRole, Name: "test", RawRef: "arn:aws:iam::1:role/test"}},
		},
		Permissions:   []providers.PermissionTuple{{IdentityID: "aws:identity:arn:aws:iam::1:role/test", Action: "s3:GetObject", Resource: "arn:aws:s3:::x/*", Effect: "Allow"}},
		Relationships: []domain.Relationship{{ID: "rel-1", Type: domain.RelationshipCanAccess, FromNodeID: "aws:identity:arn:aws:iam::1:role/test", ToNodeID: "aws:access:s3%3AGetObject:arn%3Aaws%3As3%3A%3A%3Ax%2F%2A", DiscoveredAt: now}},
	}); err != nil {
		t.Fatalf("upsert artifacts failed: %v", err)
	}
	// idempotent re-run must not fail
	if err := store.UpsertArtifacts(context.Background(), scan.ID, ScanArtifacts{}); err != nil {
		t.Fatalf("second upsert artifacts failed: %v", err)
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
	err = store.UpsertArtifacts(context.Background(), "missing", ScanArtifacts{})
	if err == nil {
		t.Fatal("expected error")
	}
	_, err = store.GetScan(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected get scan error")
	}
	_, err = store.ListFindingsByScan(context.Background(), "missing", 10)
	if err == nil {
		t.Fatal("expected findings-by-scan error")
	}
	err = store.AppendScanEvent(context.Background(), "missing", "info", "msg", nil)
	if err == nil {
		t.Fatal("expected append scan event error")
	}
	_, err = store.ListScanEvents(context.Background(), "missing", 10)
	if err == nil {
		t.Fatal("expected list scan events error")
	}
}

func TestMemoryStoreScanDetails(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	scanA, err := store.CreateScan(context.Background(), "aws", now)
	if err != nil {
		t.Fatalf("create scan A: %v", err)
	}
	scanB, err := store.CreateScan(context.Background(), "aws", now.Add(1*time.Minute))
	if err != nil {
		t.Fatalf("create scan B: %v", err)
	}

	if err := store.UpsertFindings(context.Background(), scanA.ID, []domain.Finding{
		{ID: "f1", ScanID: scanA.ID, CreatedAt: now.Add(1 * time.Second)},
		{ID: "f2", ScanID: scanA.ID, CreatedAt: now.Add(2 * time.Second)},
	}); err != nil {
		t.Fatalf("upsert findings: %v", err)
	}

	gotScan, err := store.GetScan(context.Background(), scanA.ID)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if gotScan.ID != scanA.ID {
		t.Fatalf("unexpected scan id: %q", gotScan.ID)
	}

	findings, err := store.ListFindingsByScan(context.Background(), scanA.ID, 10)
	if err != nil {
		t.Fatalf("list findings by scan: %v", err)
	}
	if len(findings) != 2 || findings[0].ID != "f2" {
		t.Fatalf("unexpected findings: %+v", findings)
	}

	if err := store.AppendScanEvent(context.Background(), scanB.ID, "info", "scan started", map[string]any{"provider": "aws"}); err != nil {
		t.Fatalf("append scan event 1: %v", err)
	}
	if err := store.AppendScanEvent(context.Background(), scanB.ID, "info", "scan completed", nil); err != nil {
		t.Fatalf("append scan event 2: %v", err)
	}
	events, err := store.ListScanEvents(context.Background(), scanB.ID, 10)
	if err != nil {
		t.Fatalf("list scan events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
}
