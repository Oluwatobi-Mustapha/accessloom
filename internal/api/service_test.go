package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/app"
	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
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

func TestServiceListFindingsFiltered(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	scanA, _ := store.CreateScan(context.Background(), "aws", now)
	scanB, _ := store.CreateScan(context.Background(), "aws", now.Add(1*time.Minute))
	_ = store.UpsertFindings(context.Background(), scanA.ID, []domain.Finding{
		{ID: "f1", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now},
	})
	_ = store.UpsertFindings(context.Background(), scanB.ID, []domain.Finding{
		{ID: "f2", Type: domain.FindingEscalationPath, Severity: domain.SeverityCritical, CreatedAt: now.Add(1 * time.Minute)},
		{ID: "f3", Type: domain.FindingOwnerless, Severity: domain.SeverityLow, CreatedAt: now.Add(1 * time.Minute)},
	})

	svc := NewService(store, fakeScanner{}, "aws")

	highOnly, err := svc.ListFindingsFiltered(context.Background(), 10, FindingsFilter{Severity: "critical"})
	if err != nil {
		t.Fatalf("list findings filtered by severity: %v", err)
	}
	if len(highOnly) != 1 || highOnly[0].ID != "f2" {
		t.Fatalf("unexpected critical findings: %+v", highOnly)
	}

	scanOnly, err := svc.ListFindingsFiltered(context.Background(), 10, FindingsFilter{ScanID: scanA.ID, Type: "ownerless_identity"})
	if err != nil {
		t.Fatalf("list findings filtered by scan/type: %v", err)
	}
	if len(scanOnly) != 1 || scanOnly[0].ID != "f1" {
		t.Fatalf("unexpected findings for scan/type: %+v", scanOnly)
	}
}

func TestServiceGetFinding(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	scan, _ := store.CreateScan(context.Background(), "aws", now)
	_ = store.UpsertFindings(context.Background(), scan.ID, []domain.Finding{
		{ID: "finding-1", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now},
	})

	svc := NewService(store, fakeScanner{}, "aws")
	found, err := svc.GetFinding(context.Background(), "finding-1", scan.ID)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	if found.ID != "finding-1" {
		t.Fatalf("unexpected finding id: %q", found.ID)
	}

	if _, err := svc.GetFinding(context.Background(), "missing", scan.ID); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected not found for missing finding, got %v", err)
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

func TestServiceGetScanDiffAgainst(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	first, _ := store.CreateScan(context.Background(), "aws", now)
	_ = store.UpsertFindings(context.Background(), first.ID, []domain.Finding{
		{ID: "persist", Severity: domain.SeverityHigh, CreatedAt: now.Add(1 * time.Second)},
		{ID: "resolved", Severity: domain.SeverityMedium, CreatedAt: now.Add(2 * time.Second)},
	})
	second, _ := store.CreateScan(context.Background(), "aws", now.Add(5*time.Minute))
	_ = store.UpsertFindings(context.Background(), second.ID, []domain.Finding{
		{ID: "persist", Severity: domain.SeverityHigh, CreatedAt: now.Add(5 * time.Minute)},
		{ID: "added", Severity: domain.SeverityCritical, CreatedAt: now.Add(6 * time.Minute)},
	})

	svc := NewService(store, fakeScanner{}, "aws")
	diff, err := svc.GetScanDiffAgainst(context.Background(), second.ID, first.ID, 10)
	if err != nil {
		t.Fatalf("get scan diff against baseline: %v", err)
	}
	if diff.PreviousScanID != first.ID || diff.AddedCount != 1 || diff.ResolvedCount != 1 {
		t.Fatalf("unexpected diff against baseline: %+v", diff)
	}
}

func TestServiceGetScanDiffAgainstRejectsInvalidBaseline(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	current, _ := store.CreateScan(context.Background(), "aws", now)
	previous, _ := store.CreateScan(context.Background(), "aws", now.Add(-5*time.Minute))
	wrongProvider, _ := store.CreateScan(context.Background(), "azure", now.Add(-10*time.Minute))
	newerBaseline, _ := store.CreateScan(context.Background(), "aws", now.Add(10*time.Minute))

	svc := NewService(store, fakeScanner{}, "aws")

	if _, err := svc.GetScanDiffAgainst(context.Background(), current.ID, current.ID, 10); !errors.Is(err, ErrInvalidScanDiffBaseline) {
		t.Fatalf("expected invalid baseline when baseline==current, got %v", err)
	}
	if _, err := svc.GetScanDiffAgainst(context.Background(), current.ID, wrongProvider.ID, 10); !errors.Is(err, ErrInvalidScanDiffBaseline) {
		t.Fatalf("expected invalid baseline provider error, got %v", err)
	}
	if _, err := svc.GetScanDiffAgainst(context.Background(), current.ID, newerBaseline.ID, 10); !errors.Is(err, ErrInvalidScanDiffBaseline) {
		t.Fatalf("expected invalid baseline time ordering error, got %v", err)
	}
	if _, err := svc.GetScanDiffAgainst(context.Background(), current.ID, previous.ID, 10); err != nil {
		t.Fatalf("expected valid older baseline, got %v", err)
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

	if err := store.AppendScanEvent(context.Background(), result.Scan.ID, db.ScanEventLevelError, "forced error", nil); err != nil {
		t.Fatalf("append error event: %v", err)
	}
	errorEvents, err := svc.ListScanEventsFiltered(context.Background(), result.Scan.ID, db.ScanEventLevelError, 20)
	if err != nil {
		t.Fatalf("list filtered scan events: %v", err)
	}
	if len(errorEvents) == 0 {
		t.Fatal("expected at least one error-level event")
	}
}

func TestServiceListIdentitiesAndRelationshipsDefaultsToLatestScan(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	scanA, err := store.CreateScan(context.Background(), "aws", now)
	if err != nil {
		t.Fatalf("create scan A: %v", err)
	}
	if err := store.UpsertArtifacts(context.Background(), scanA.ID, db.ScanArtifacts{
		Bundle: providers.NormalizedBundle{
			Identities: []domain.Identity{{ID: "id-1", Provider: domain.ProviderAWS, Type: domain.IdentityTypeRole, Name: "app-a", RawRef: "raw-a"}},
		},
		Relationships: []domain.Relationship{{ID: "rel-1", Type: domain.RelationshipCanAssume, FromNodeID: "id-1", ToNodeID: "id-2", DiscoveredAt: now}},
	}); err != nil {
		t.Fatalf("seed artifacts A: %v", err)
	}

	scanB, err := store.CreateScan(context.Background(), "aws", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("create scan B: %v", err)
	}
	if err := store.UpsertArtifacts(context.Background(), scanB.ID, db.ScanArtifacts{
		Bundle: providers.NormalizedBundle{
			Identities: []domain.Identity{{ID: "id-2", Provider: domain.ProviderAWS, Type: domain.IdentityTypeRole, Name: "app-b", RawRef: "raw-b"}},
		},
		Relationships: []domain.Relationship{{ID: "rel-2", Type: domain.RelationshipCanAccess, FromNodeID: "id-2", ToNodeID: "bucket-1", DiscoveredAt: now.Add(1 * time.Minute)}},
	}); err != nil {
		t.Fatalf("seed artifacts B: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	identities, err := svc.ListIdentities(context.Background(), "", "aws", "role", "app", 10)
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	if len(identities) != 1 || identities[0].ID != "id-2" {
		t.Fatalf("unexpected identities from latest scan: %+v", identities)
	}

	relationships, err := svc.ListRelationships(context.Background(), "", "can_access", "", "", 10)
	if err != nil {
		t.Fatalf("list relationships: %v", err)
	}
	if len(relationships) != 1 || relationships[0].ID != "rel-2" {
		t.Fatalf("unexpected relationships from latest scan: %+v", relationships)
	}
}

func TestServiceGetFindingsTrend(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	scanA, _ := store.CreateScan(context.Background(), "aws", now)
	_ = store.UpsertFindings(context.Background(), scanA.ID, []domain.Finding{
		{ID: "f1", Severity: domain.SeverityHigh, CreatedAt: now},
	})
	scanB, _ := store.CreateScan(context.Background(), "aws", now.Add(3*time.Minute))
	_ = store.UpsertFindings(context.Background(), scanB.ID, []domain.Finding{
		{ID: "f2", Severity: domain.SeverityCritical, CreatedAt: now.Add(3 * time.Minute)},
		{ID: "f3", Severity: domain.SeverityMedium, CreatedAt: now.Add(3 * time.Minute)},
	})

	svc := NewService(store, fakeScanner{}, "aws")
	points, err := svc.GetFindingsTrend(context.Background(), 10)
	if err != nil {
		t.Fatalf("get findings trend: %v", err)
	}
	if len(points) != 2 {
		t.Fatalf("expected 2 trend points, got %d", len(points))
	}
	if points[0].ScanID != scanA.ID || points[1].ScanID != scanB.ID {
		t.Fatalf("unexpected trend order: %+v", points)
	}
	if points[1].BySeverity["critical"] != 1 {
		t.Fatalf("unexpected severity bucket: %+v", points[1].BySeverity)
	}
}

func TestServiceGetFindingsTrendFiltered(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	scan, _ := store.CreateScan(context.Background(), "aws", now)
	_ = store.UpsertFindings(context.Background(), scan.ID, []domain.Finding{
		{ID: "f1", Severity: domain.SeverityCritical, Type: domain.FindingEscalationPath, CreatedAt: now},
		{ID: "f2", Severity: domain.SeverityHigh, Type: domain.FindingOwnerless, CreatedAt: now},
	})

	svc := NewService(store, fakeScanner{}, "aws")
	points, err := svc.GetFindingsTrendFiltered(context.Background(), 10, "critical", "escalation_path")
	if err != nil {
		t.Fatalf("trend filtered: %v", err)
	}
	if len(points) != 1 || points[0].Total != 1 {
		t.Fatalf("unexpected filtered points: %+v", points)
	}
}
