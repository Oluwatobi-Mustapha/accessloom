package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/app"
	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/scheduler"
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

type fakeAlerter struct {
	calls int
	err   error
}

func (a *fakeAlerter) NotifyScan(context.Context, string, db.ScanRecord, []domain.Finding) error {
	a.calls++
	return a.err
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

func TestServiceRunScanLocked(t *testing.T) {
	store := db.NewMemoryStore()
	locker := scheduler.NewInMemoryLocker()
	release, ok := locker.TryAcquire("scan:aws")
	if !ok {
		t.Fatal("expected lock acquire")
	}
	defer release()

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Locker = locker

	_, err := svc.RunScan(context.Background())
	if !errors.Is(err, ErrScanInProgress) {
		t.Fatalf("expected ErrScanInProgress, got %v", err)
	}
}

func TestServiceRunScanAlertHookCalled(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	alerter := &fakeAlerter{}
	svc := NewService(store, fakeScanner{result: app.ScanResult{
		Assets:   1,
		Findings: []domain.Finding{{ID: "f1", Severity: domain.SeverityHigh}},
	}}, "aws")
	svc.Now = func() time.Time { return now }
	svc.Alerter = alerter

	if _, err := svc.RunScan(context.Background()); err != nil {
		t.Fatalf("run scan: %v", err)
	}
	if alerter.calls != 1 {
		t.Fatalf("expected 1 alert call, got %d", alerter.calls)
	}
}

func TestServiceRunScanAlertFailureIsNonBlocking(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	alerter := &fakeAlerter{err: errors.New("webhook down")}
	svc := NewService(store, fakeScanner{result: app.ScanResult{
		Assets:   1,
		Findings: []domain.Finding{{ID: "f1", Severity: domain.SeverityHigh}},
	}}, "aws")
	svc.Now = func() time.Time { return now }
	svc.Alerter = alerter

	errorCalls := 0
	svc.OnAlertError = func(err error) {
		if err != nil {
			errorCalls++
		}
	}

	result, err := svc.RunScan(context.Background())
	if err != nil {
		t.Fatalf("expected scan success despite alert error, got %v", err)
	}
	if result.Scan.Status != "completed" {
		t.Fatalf("expected completed status, got %q", result.Scan.Status)
	}
	if errorCalls != 1 {
		t.Fatalf("expected alert error callback once, got %d", errorCalls)
	}
}

func TestServiceGetFindingsSummary(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	scan, err := store.CreateScan(context.Background(), "aws", now)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := store.UpsertFindings(context.Background(), scan.ID, []domain.Finding{
		{ID: "f1", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now},
		{ID: "f2", Type: domain.FindingOwnerless, Severity: domain.SeverityMedium, CreatedAt: now},
		{ID: "f3", Type: domain.FindingStaleIdentity, Severity: domain.SeverityHigh, CreatedAt: now},
	}); err != nil {
		t.Fatalf("upsert findings: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	summary, err := svc.GetFindingsSummary(context.Background(), 100)
	if err != nil {
		t.Fatalf("get summary: %v", err)
	}
	if summary.Total != 3 {
		t.Fatalf("expected total 3, got %d", summary.Total)
	}
	if summary.BySeverity["high"] != 2 {
		t.Fatalf("unexpected severity summary: %+v", summary.BySeverity)
	}
	if summary.ByType["ownerless_identity"] != 2 {
		t.Fatalf("unexpected type summary: %+v", summary.ByType)
	}
}

func TestServiceGetScanDiff(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	first, err := store.CreateScan(context.Background(), "aws", now)
	if err != nil {
		t.Fatalf("create first scan: %v", err)
	}
	if err := store.UpsertFindings(context.Background(), first.ID, []domain.Finding{
		{ID: "persist", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now.Add(1 * time.Second)},
		{ID: "resolved", Type: domain.FindingStaleIdentity, Severity: domain.SeverityMedium, CreatedAt: now.Add(2 * time.Second)},
	}); err != nil {
		t.Fatalf("seed first findings: %v", err)
	}

	second, err := store.CreateScan(context.Background(), "aws", now.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("create second scan: %v", err)
	}
	if err := store.UpsertFindings(context.Background(), second.ID, []domain.Finding{
		{ID: "persist", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now.Add(11 * time.Minute)},
		{ID: "added", Type: domain.FindingEscalationPath, Severity: domain.SeverityCritical, CreatedAt: now.Add(12 * time.Minute)},
	}); err != nil {
		t.Fatalf("seed second findings: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	diff, err := svc.GetScanDiff(context.Background(), second.ID, 10)
	if err != nil {
		t.Fatalf("get scan diff: %v", err)
	}
	if diff.PreviousScanID != first.ID {
		t.Fatalf("expected previous scan %q, got %q", first.ID, diff.PreviousScanID)
	}
	if diff.AddedCount != 1 || diff.ResolvedCount != 1 || diff.PersistingCount != 1 {
		t.Fatalf("unexpected diff counts: %+v", diff)
	}
}

func TestServiceListScanEvents(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{result: app.ScanResult{}}, "aws")
	svc.Now = func() time.Time { return time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC) }

	result, err := svc.RunScan(context.Background())
	if err != nil {
		t.Fatalf("run scan: %v", err)
	}
	events, err := svc.ListScanEvents(context.Background(), result.Scan.ID, 10)
	if err != nil {
		t.Fatalf("list scan events: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected scan events")
	}
}
