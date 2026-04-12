package api

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/app"
	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
	"github.com/Oluwatobi-Mustapha/identrail/internal/repoexposure"
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

type fakeRepoExecutor struct {
	result repoexposure.ScanResult
	err    error
	target string
}

func (f *fakeRepoExecutor) ScanRepository(_ context.Context, target string) (repoexposure.ScanResult, error) {
	f.target = target
	if f.err != nil {
		return repoexposure.ScanResult{}, f.err
	}
	return f.result, nil
}

func TestServiceCheckReadiness(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{}, "aws")
	if err := svc.CheckReadiness(context.Background()); err != nil {
		t.Fatalf("expected readiness check to pass, got %v", err)
	}
}

func TestServiceCheckReadinessDependencyFailure(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{}, "aws")
	svc.ReadinessCheck = func(context.Context) error {
		return errors.New("dependency unavailable")
	}
	if err := svc.CheckReadiness(context.Background()); err == nil {
		t.Fatal("expected readiness check failure")
	}
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

	result, err := svc.RunScan(defaultScopeContext())
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

	_, err := svc.RunScan(defaultScopeContext())
	if err == nil {
		t.Fatal("expected error")
	}

	scans, listErr := store.ListScans(defaultScopeContext(), 1)
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
	release, ok := locker.TryAcquire("identrail:scan:aws")
	if !ok {
		t.Fatal("expected lock acquire")
	}
	defer release()

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Locker = locker

	_, err := svc.RunScan(defaultScopeContext())
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

	if _, err := svc.RunScan(defaultScopeContext()); err != nil {
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

	result, err := svc.RunScan(defaultScopeContext())
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
	scan, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), scan.ID, []domain.Finding{
		{ID: "f1", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now},
		{ID: "f2", Type: domain.FindingOwnerless, Severity: domain.SeverityMedium, CreatedAt: now},
		{ID: "f3", Type: domain.FindingStaleIdentity, Severity: domain.SeverityHigh, CreatedAt: now},
	}); err != nil {
		t.Fatalf("upsert findings: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	summary, err := svc.GetFindingsSummary(defaultScopeContext(), 100)
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
	scanA, _ := store.CreateScan(defaultScopeContext(), "aws", now)
	scanB, _ := store.CreateScan(defaultScopeContext(), "aws", now.Add(1*time.Minute))
	_ = store.UpsertFindings(defaultScopeContext(), scanA.ID, []domain.Finding{
		{ID: "f1", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now},
	})
	_ = store.UpsertFindings(defaultScopeContext(), scanB.ID, []domain.Finding{
		{ID: "f2", Type: domain.FindingEscalationPath, Severity: domain.SeverityCritical, CreatedAt: now.Add(1 * time.Minute)},
		{ID: "f3", Type: domain.FindingOwnerless, Severity: domain.SeverityLow, CreatedAt: now.Add(1 * time.Minute)},
	})

	svc := NewService(store, fakeScanner{}, "aws")

	highOnly, err := svc.ListFindingsFiltered(defaultScopeContext(), 10, FindingsFilter{Severity: "critical"})
	if err != nil {
		t.Fatalf("list findings filtered by severity: %v", err)
	}
	if len(highOnly) != 1 || highOnly[0].ID != "f2" {
		t.Fatalf("unexpected critical findings: %+v", highOnly)
	}

	scanOnly, err := svc.ListFindingsFiltered(defaultScopeContext(), 10, FindingsFilter{ScanID: scanA.ID, Type: "ownerless_identity"})
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
	scan, _ := store.CreateScan(defaultScopeContext(), "aws", now)
	_ = store.UpsertFindings(defaultScopeContext(), scan.ID, []domain.Finding{
		{ID: "finding-1", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now},
	})

	svc := NewService(store, fakeScanner{}, "aws")
	found, err := svc.GetFinding(defaultScopeContext(), "finding-1", scan.ID)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	if found.ID != "finding-1" {
		t.Fatalf("unexpected finding id: %q", found.ID)
	}

	if _, err := svc.GetFinding(defaultScopeContext(), "missing", scan.ID); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected not found for missing finding, got %v", err)
	}
}

func TestServiceFindingTriageLifecycleAndHistory(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 22, 9, 0, 0, 0, time.UTC)
	scan, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), scan.ID, []domain.Finding{
		{ID: "finding-1", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now},
	}); err != nil {
		t.Fatalf("upsert findings: %v", err)
	}

	clock := now
	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return clock }

	initial, err := svc.GetFinding(defaultScopeContext(), "finding-1", scan.ID)
	if err != nil {
		t.Fatalf("get initial finding: %v", err)
	}
	if initial.Triage.Status != domain.FindingLifecycleOpen {
		t.Fatalf("expected default open status, got %q", initial.Triage.Status)
	}

	suppressed := string(domain.FindingLifecycleSuppressed)
	assignee := "secops"
	suppressionExpiry := clock.Add(2 * time.Hour).Format(time.RFC3339)
	updated, err := svc.TriageFinding(
		defaultScopeContext(),
		"finding-1",
		scan.ID,
		FindingTriageRequest{
			Status:               &suppressed,
			Assignee:             &assignee,
			SuppressionExpiresAt: &suppressionExpiry,
			Comment:              "accepted risk until patch lands",
		},
		"subject:user-1",
	)
	if err != nil {
		t.Fatalf("triage finding: %v", err)
	}
	if updated.Triage.Status != domain.FindingLifecycleSuppressed {
		t.Fatalf("expected suppressed status, got %q", updated.Triage.Status)
	}
	if updated.Triage.Assignee != "secops" {
		t.Fatalf("expected assignee secops, got %q", updated.Triage.Assignee)
	}
	if updated.Triage.SuppressionExpiresAt == nil {
		t.Fatal("expected suppression expiry to be set")
	}
	if updated.Triage.UpdatedBy != "subject:user-1" {
		t.Fatalf("expected triage actor to be persisted, got %q", updated.Triage.UpdatedBy)
	}

	history, err := svc.ListFindingTriageHistory(defaultScopeContext(), "finding-1", scan.ID, 10)
	if err != nil {
		t.Fatalf("list triage history: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("expected one triage event, got %d", len(history))
	}
	if history[0].Action != db.FindingTriageActionSuppressed {
		t.Fatalf("expected suppressed action, got %q", history[0].Action)
	}
	if history[0].FromStatus != domain.FindingLifecycleOpen || history[0].ToStatus != domain.FindingLifecycleSuppressed {
		t.Fatalf("unexpected status transition: %+v", history[0])
	}

	suppressedItems, err := svc.ListFindingsFiltered(defaultScopeContext(), 10, FindingsFilter{
		LifecycleStatus: "suppressed",
		Assignee:        "SECOPS",
	})
	if err != nil {
		t.Fatalf("list suppressed findings: %v", err)
	}
	if len(suppressedItems) != 1 || suppressedItems[0].ID != "finding-1" {
		t.Fatalf("unexpected suppressed filter result: %+v", suppressedItems)
	}

	clock = clock.Add(3 * time.Hour)
	reopened, err := svc.GetFinding(defaultScopeContext(), "finding-1", scan.ID)
	if err != nil {
		t.Fatalf("get finding after suppression expiry: %v", err)
	}
	if reopened.Triage.Status != domain.FindingLifecycleOpen {
		t.Fatalf("expected suppression expiry to reopen finding, got %q", reopened.Triage.Status)
	}
	if reopened.Triage.SuppressionExpiresAt != nil {
		t.Fatalf("expected suppression expiry cleared after expiration, got %v", reopened.Triage.SuppressionExpiresAt)
	}
}

func TestServiceTriageFindingRejectsInvalidRequest(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 22, 9, 0, 0, 0, time.UTC)
	scan, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), scan.ID, []domain.Finding{
		{ID: "finding-1", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now},
	}); err != nil {
		t.Fatalf("upsert findings: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	svc.Now = func() time.Time { return now }

	if _, err := svc.TriageFinding(defaultScopeContext(), "finding-1", scan.ID, FindingTriageRequest{}, "subject:user-1"); !errors.Is(err, ErrInvalidFindingTriageRequest) {
		t.Fatalf("expected invalid triage request error for empty payload, got %v", err)
	}

	suppressed := string(domain.FindingLifecycleSuppressed)
	pastExpiry := now.Add(-1 * time.Hour).Format(time.RFC3339)
	if _, err := svc.TriageFinding(
		defaultScopeContext(),
		"finding-1",
		scan.ID,
		FindingTriageRequest{
			Status:               &suppressed,
			SuppressionExpiresAt: &pastExpiry,
		},
		"subject:user-1",
	); !errors.Is(err, ErrInvalidFindingTriageRequest) {
		t.Fatalf("expected invalid triage request error for past suppression expiry, got %v", err)
	}
}

func TestServiceGetFindingExports(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	scan, _ := store.CreateScan(defaultScopeContext(), "aws", now)
	_ = store.UpsertFindings(defaultScopeContext(), scan.ID, []domain.Finding{
		{
			ID:        "finding-1",
			Type:      domain.FindingOverPrivileged,
			Severity:  domain.SeverityHigh,
			Title:     "Overprivileged role",
			CreatedAt: now,
		},
	})

	svc := NewService(store, fakeScanner{}, "aws")
	exports, err := svc.GetFindingExports(defaultScopeContext(), "finding-1", scan.ID)
	if err != nil {
		t.Fatalf("get finding exports: %v", err)
	}
	findingInfo, ok := exports.OCSF["finding_info"].(map[string]any)
	if !ok {
		t.Fatalf("expected finding_info object, got %+v", exports.OCSF)
	}
	if findingInfo["uid"] != "finding-1" {
		t.Fatalf("expected OCSF payload, got %+v", exports.OCSF)
	}
	if exports.ASFF["SchemaVersion"] != "2018-10-08" {
		t.Fatalf("expected ASFF schema version, got %+v", exports.ASFF)
	}
}

func TestServiceGetScanDiff(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	first, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create first scan: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), first.ID, []domain.Finding{
		{ID: "persist", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now.Add(1 * time.Second)},
		{ID: "resolved", Type: domain.FindingStaleIdentity, Severity: domain.SeverityMedium, CreatedAt: now.Add(2 * time.Second)},
	}); err != nil {
		t.Fatalf("seed first findings: %v", err)
	}

	second, err := store.CreateScan(defaultScopeContext(), "aws", now.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("create second scan: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), second.ID, []domain.Finding{
		{ID: "persist", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now.Add(11 * time.Minute)},
		{ID: "added", Type: domain.FindingEscalationPath, Severity: domain.SeverityCritical, CreatedAt: now.Add(12 * time.Minute)},
	}); err != nil {
		t.Fatalf("seed second findings: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	diff, err := svc.GetScanDiff(defaultScopeContext(), second.ID, 10)
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

	first, _ := store.CreateScan(defaultScopeContext(), "aws", now)
	_ = store.UpsertFindings(defaultScopeContext(), first.ID, []domain.Finding{
		{ID: "persist", Severity: domain.SeverityHigh, CreatedAt: now.Add(1 * time.Second)},
		{ID: "resolved", Severity: domain.SeverityMedium, CreatedAt: now.Add(2 * time.Second)},
	})
	second, _ := store.CreateScan(defaultScopeContext(), "aws", now.Add(5*time.Minute))
	_ = store.UpsertFindings(defaultScopeContext(), second.ID, []domain.Finding{
		{ID: "persist", Severity: domain.SeverityHigh, CreatedAt: now.Add(5 * time.Minute)},
		{ID: "added", Severity: domain.SeverityCritical, CreatedAt: now.Add(6 * time.Minute)},
	})

	svc := NewService(store, fakeScanner{}, "aws")
	diff, err := svc.GetScanDiffAgainst(defaultScopeContext(), second.ID, first.ID, 10)
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

	current, _ := store.CreateScan(defaultScopeContext(), "aws", now)
	previous, _ := store.CreateScan(defaultScopeContext(), "aws", now.Add(-5*time.Minute))
	wrongProvider, _ := store.CreateScan(defaultScopeContext(), "azure", now.Add(-10*time.Minute))
	newerBaseline, _ := store.CreateScan(defaultScopeContext(), "aws", now.Add(10*time.Minute))

	svc := NewService(store, fakeScanner{}, "aws")

	if _, err := svc.GetScanDiffAgainst(defaultScopeContext(), current.ID, current.ID, 10); !errors.Is(err, ErrInvalidScanDiffBaseline) {
		t.Fatalf("expected invalid baseline when baseline==current, got %v", err)
	}
	if _, err := svc.GetScanDiffAgainst(defaultScopeContext(), current.ID, wrongProvider.ID, 10); !errors.Is(err, ErrInvalidScanDiffBaseline) {
		t.Fatalf("expected invalid baseline provider error, got %v", err)
	}
	if _, err := svc.GetScanDiffAgainst(defaultScopeContext(), current.ID, newerBaseline.ID, 10); !errors.Is(err, ErrInvalidScanDiffBaseline) {
		t.Fatalf("expected invalid baseline time ordering error, got %v", err)
	}
	if _, err := svc.GetScanDiffAgainst(defaultScopeContext(), current.ID, previous.ID, 10); err != nil {
		t.Fatalf("expected valid older baseline, got %v", err)
	}
}

func TestServiceListScanEvents(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{result: app.ScanResult{}}, "aws")
	svc.Now = func() time.Time { return time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC) }

	result, err := svc.RunScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("run scan: %v", err)
	}
	events, err := svc.ListScanEvents(defaultScopeContext(), result.Scan.ID, 10)
	if err != nil {
		t.Fatalf("list scan events: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected scan events")
	}

	if err := store.AppendScanEvent(defaultScopeContext(), result.Scan.ID, db.ScanEventLevelError, "forced error", nil); err != nil {
		t.Fatalf("append error event: %v", err)
	}
	errorEvents, err := svc.ListScanEventsFiltered(defaultScopeContext(), result.Scan.ID, db.ScanEventLevelError, 20)
	if err != nil {
		t.Fatalf("list filtered scan events: %v", err)
	}
	if len(errorEvents) == 0 {
		t.Fatal("expected at least one error-level event")
	}
}

func TestServiceRunScanPartialLifecycleEvents(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 19, 10, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{result: app.ScanResult{
		Assets: 1,
		Bundle: providers.NormalizedBundle{
			Identities: []domain.Identity{{
				ID:       "aws:identity:arn:aws:iam::123456789012:role/demo",
				Provider: domain.ProviderAWS,
				Type:     domain.IdentityTypeRole,
				Name:     "demo",
			}},
		},
		SourceErrors: []providers.SourceError{{
			Collector: "aws_iam_collector",
			Code:      "missing_role_arn",
			Message:   "skipped IAM role record without ARN",
		}},
	}}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.RunScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("run scan: %v", err)
	}
	if result.Scan.Status != "completed" {
		t.Fatalf("expected completed scan status, got %q", result.Scan.Status)
	}

	events, err := svc.ListScanEvents(defaultScopeContext(), result.Scan.ID, 50)
	if err != nil {
		t.Fatalf("list scan events: %v", err)
	}
	states := map[string]bool{}
	for _, event := range events {
		state, _ := event.Metadata["state"].(string)
		if state != "" {
			states[state] = true
		}
	}
	for _, expected := range []string{scanLifecycleQueued, scanLifecycleRunning, scanLifecyclePartial, scanLifecycleSucceeded} {
		if !states[expected] {
			t.Fatalf("expected lifecycle state %q in events, got %+v", expected, states)
		}
	}
}

func TestServiceRunScanPersistsRawAndNormalizedArtifactsConsistently(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 20, 11, 0, 0, 0, time.UTC)
	identityID := "aws:identity:arn:aws:iam::123456789012:role/demo"
	policyID := "aws:policy:demo"
	relationshipID := "rel-attached-policy"

	svc := NewService(store, fakeScanner{result: app.ScanResult{
		Assets: 1,
		RawAssets: []providers.RawAsset{
			{
				Kind:      "aws_iam_role",
				SourceID:  "arn:aws:iam::123456789012:role/demo",
				Payload:   []byte(`{"RoleName":"demo"}`),
				Collected: now.Format(time.RFC3339Nano),
			},
		},
		Bundle: providers.NormalizedBundle{
			Identities: []domain.Identity{
				{
					ID:       identityID,
					Provider: domain.ProviderAWS,
					Type:     domain.IdentityTypeRole,
					Name:     "demo",
					ARN:      "arn:aws:iam::123456789012:role/demo",
					RawRef:   "aws_iam_role:arn:aws:iam::123456789012:role/demo",
				},
			},
			Policies: []domain.Policy{
				{
					ID:       policyID,
					Provider: domain.ProviderAWS,
					Name:     "demo-inline",
					RawRef:   "aws_iam_policy:demo-inline",
					Normalized: map[string]any{
						"policy_type": "permission",
						"identity_id": identityID,
						"statements": []map[string]any{
							{"effect": "Allow", "actions": []string{"s3:GetObject"}, "resources": []string{"*"}},
						},
					},
				},
			},
		},
		Permissions: []providers.PermissionTuple{
			{
				IdentityID: identityID,
				Action:     "s3:GetObject",
				Resource:   "*",
				Effect:     "Allow",
			},
		},
		Relationships: []domain.Relationship{
			{
				ID:           relationshipID,
				Type:         domain.RelationshipAttachedPolicy,
				FromNodeID:   identityID,
				ToNodeID:     policyID,
				DiscoveredAt: now,
			},
		},
		Findings: []domain.Finding{
			{
				ID:           "finding-ownerless",
				Type:         domain.FindingOwnerless,
				Severity:     domain.SeverityMedium,
				Title:        "Ownerless identity",
				HumanSummary: "Identity has no owner hint",
				Remediation:  "Assign team owner",
				CreatedAt:    now,
			},
		},
	}}, "aws")
	svc.Now = func() time.Time { return now }

	result, err := svc.RunScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("run scan: %v", err)
	}
	if result.Assets != 1 || result.FindingCount != 1 {
		t.Fatalf("unexpected run result: %+v", result)
	}

	identities, err := svc.ListIdentities(defaultScopeContext(), result.Scan.ID, "aws", "role", "", 10)
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	if len(identities) != 1 || identities[0].ID != identityID {
		t.Fatalf("unexpected identities: %+v", identities)
	}

	relationships, err := svc.ListRelationships(defaultScopeContext(), result.Scan.ID, string(domain.RelationshipAttachedPolicy), "", "", 10)
	if err != nil {
		t.Fatalf("list relationships: %v", err)
	}
	if len(relationships) != 1 || relationships[0].ID != relationshipID {
		t.Fatalf("unexpected relationships: %+v", relationships)
	}

	findings, err := svc.ListFindingsFiltered(defaultScopeContext(), 10, FindingsFilter{ScanID: result.Scan.ID})
	if err != nil {
		t.Fatalf("list findings filtered: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "finding-ownerless" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

func TestServiceListIdentitiesAndRelationshipsDefaultsToLatestScan(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	scanA, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan A: %v", err)
	}
	if err := store.UpsertArtifacts(defaultScopeContext(), scanA.ID, db.ScanArtifacts{
		Bundle: providers.NormalizedBundle{
			Identities: []domain.Identity{{ID: "id-1", Provider: domain.ProviderAWS, Type: domain.IdentityTypeRole, Name: "app-a", RawRef: "raw-a"}},
		},
		Relationships: []domain.Relationship{{ID: "rel-1", Type: domain.RelationshipCanAssume, FromNodeID: "id-1", ToNodeID: "id-2", DiscoveredAt: now}},
	}); err != nil {
		t.Fatalf("seed artifacts A: %v", err)
	}

	scanB, err := store.CreateScan(defaultScopeContext(), "aws", now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("create scan B: %v", err)
	}
	if err := store.UpsertArtifacts(defaultScopeContext(), scanB.ID, db.ScanArtifacts{
		Bundle: providers.NormalizedBundle{
			Identities: []domain.Identity{{ID: "id-2", Provider: domain.ProviderAWS, Type: domain.IdentityTypeRole, Name: "app-b", RawRef: "raw-b"}},
		},
		Relationships: []domain.Relationship{{ID: "rel-2", Type: domain.RelationshipCanAccess, FromNodeID: "id-2", ToNodeID: "bucket-1", DiscoveredAt: now.Add(1 * time.Minute)}},
	}); err != nil {
		t.Fatalf("seed artifacts B: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	identities, err := svc.ListIdentities(defaultScopeContext(), "", "aws", "role", "app", 10)
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	if len(identities) != 1 || identities[0].ID != "id-2" {
		t.Fatalf("unexpected identities from latest scan: %+v", identities)
	}

	relationships, err := svc.ListRelationships(defaultScopeContext(), "", "can_access", "", "", 10)
	if err != nil {
		t.Fatalf("list relationships: %v", err)
	}
	if len(relationships) != 1 || relationships[0].ID != "rel-2" {
		t.Fatalf("unexpected relationships from latest scan: %+v", relationships)
	}
}

func TestServiceListOwnershipSignals(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 17, 18, 0, 0, 0, time.UTC)
	scan, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := store.UpsertArtifacts(defaultScopeContext(), scan.ID, db.ScanArtifacts{
		Bundle: providers.NormalizedBundle{
			Identities: []domain.Identity{
				{
					ID:        "id-owner-hint",
					Provider:  domain.ProviderAWS,
					Type:      domain.IdentityTypeRole,
					Name:      "app-a",
					OwnerHint: "platform",
					RawRef:    "raw-a",
				},
				{
					ID:       "id-tags",
					Provider: domain.ProviderAWS,
					Type:     domain.IdentityTypeRole,
					Name:     "app-b",
					Tags: map[string]string{
						"team":       "payments",
						"repository": "github.com/acme/payments",
					},
					RawRef: "raw-b",
				},
			},
		},
	}); err != nil {
		t.Fatalf("upsert artifacts: %v", err)
	}

	svc := NewService(store, fakeScanner{}, "aws")
	signals, err := svc.ListOwnershipSignals(defaultScopeContext(), 10, OwnershipFilter{ScanID: scan.ID})
	if err != nil {
		t.Fatalf("list ownership signals: %v", err)
	}
	if len(signals) != 2 {
		t.Fatalf("expected 2 ownership signals, got %d", len(signals))
	}
	if signals[0].IdentityID != "id-owner-hint" || signals[0].Source != "owner_hint" {
		t.Fatalf("unexpected top signal %+v", signals[0])
	}
}

func TestServiceGetFindingsTrend(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	scanA, _ := store.CreateScan(defaultScopeContext(), "aws", now)
	_ = store.UpsertFindings(defaultScopeContext(), scanA.ID, []domain.Finding{
		{ID: "f1", Severity: domain.SeverityHigh, CreatedAt: now},
	})
	scanB, _ := store.CreateScan(defaultScopeContext(), "aws", now.Add(3*time.Minute))
	_ = store.UpsertFindings(defaultScopeContext(), scanB.ID, []domain.Finding{
		{ID: "f2", Severity: domain.SeverityCritical, CreatedAt: now.Add(3 * time.Minute)},
		{ID: "f3", Severity: domain.SeverityMedium, CreatedAt: now.Add(3 * time.Minute)},
	})

	svc := NewService(store, fakeScanner{}, "aws")
	points, err := svc.GetFindingsTrend(defaultScopeContext(), 10)
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
	scan, _ := store.CreateScan(defaultScopeContext(), "aws", now)
	_ = store.UpsertFindings(defaultScopeContext(), scan.ID, []domain.Finding{
		{ID: "f1", Severity: domain.SeverityCritical, Type: domain.FindingEscalationPath, CreatedAt: now},
		{ID: "f2", Severity: domain.SeverityHigh, Type: domain.FindingOwnerless, CreatedAt: now},
	})

	svc := NewService(store, fakeScanner{}, "aws")
	points, err := svc.GetFindingsTrendFiltered(defaultScopeContext(), 10, "critical", "escalation_path")
	if err != nil {
		t.Fatalf("trend filtered: %v", err)
	}
	if len(points) != 1 || points[0].Total != 1 {
		t.Fatalf("unexpected filtered points: %+v", points)
	}
}

func TestServiceRunRepoScanSuccess(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	executor := &fakeRepoExecutor{
		result: repoexposure.ScanResult{
			Repository:     "owner/repo",
			CommitsScanned: 10,
			FilesScanned:   4,
			Findings: []domain.Finding{
				{ID: "f1", Type: domain.FindingSecretExposure, Severity: domain.SeverityHigh},
			},
		},
	}
	var gotHistory, gotMax int
	svc.RepoScannerFactory = func(historyLimit int, maxFindings int) RepoScanExecutor {
		gotHistory, gotMax = historyLimit, maxFindings
		return executor
	}

	result, err := svc.RunRepoScan(defaultScopeContext(), RepoScanRequest{
		Repository:   "owner/repo",
		HistoryLimit: 800,
		MaxFindings:  300,
	})
	if err != nil {
		t.Fatalf("run repo scan: %v", err)
	}
	if result.Repository != "owner/repo" || len(result.Findings) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if executor.target != "owner/repo" {
		t.Fatalf("unexpected scan target: %q", executor.target)
	}
	if gotHistory != 800 || gotMax != 300 {
		t.Fatalf("unexpected scanner args history=%d max=%d", gotHistory, gotMax)
	}
}

func TestServiceRunRepoScanPersistedStoresRecords(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	svc.Now = func() time.Time { return time.Date(2026, 3, 17, 15, 0, 0, 0, time.UTC) }
	svc.RepoScannerFactory = func(historyLimit int, maxFindings int) RepoScanExecutor {
		return &fakeRepoExecutor{
			result: repoexposure.ScanResult{
				Repository:     "owner/repo",
				CommitsScanned: historyLimit,
				FilesScanned:   5,
				Findings: []domain.Finding{
					{ID: "rf-1", Type: domain.FindingSecretExposure, Severity: domain.SeverityHigh, CreatedAt: time.Now().UTC()},
				},
				Truncated: false,
			},
		}
	}
	run, err := svc.RunRepoScanPersisted(defaultScopeContext(), RepoScanRequest{
		Repository:   "owner/repo",
		HistoryLimit: 10,
		MaxFindings:  20,
	})
	if err != nil {
		t.Fatalf("run repo scan persisted: %v", err)
	}
	if run.RepoScan.ID == "" || run.RepoScan.Status != "completed" || run.RepoScan.FindingCount != 1 {
		t.Fatalf("unexpected repo scan run result: %+v", run)
	}

	stored, err := svc.GetRepoScan(defaultScopeContext(), run.RepoScan.ID)
	if err != nil {
		t.Fatalf("get repo scan: %v", err)
	}
	if stored.ID != run.RepoScan.ID || stored.CommitsScanned != 10 {
		t.Fatalf("unexpected persisted repo scan: %+v", stored)
	}

	findings, err := svc.ListRepoFindings(defaultScopeContext(), 10, db.RepoFindingFilter{RepoScanID: run.RepoScan.ID})
	if err != nil {
		t.Fatalf("list repo findings: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "rf-1" {
		t.Fatalf("unexpected persisted repo findings: %+v", findings)
	}
}

func TestServiceRunRepoScanGuards(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{}, "aws")
	svc.RepoScanEnabled = false
	if _, err := svc.RunRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo"}); !errors.Is(err, ErrRepoScanDisabled) {
		t.Fatalf("expected disabled error, got %v", err)
	}

	svc.RepoScanEnabled = true
	svc.RepoScanAllowedTargets = []string{"trusted/*"}
	if _, err := svc.RunRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo"}); !errors.Is(err, ErrRepoTargetNotAllowed) {
		t.Fatalf("expected target not allowed error, got %v", err)
	}

	svc.RepoScanAllowedTargets = nil
	if _, err := svc.RunRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "", HistoryLimit: 10, MaxFindings: 10}); !errors.Is(err, ErrInvalidRepoScanRequest) {
		t.Fatalf("expected invalid request error for missing repo, got %v", err)
	}

	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	if _, err := svc.RunRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo", HistoryLimit: -1, MaxFindings: 10}); !errors.Is(err, ErrInvalidRepoScanRequest) {
		t.Fatalf("expected invalid request error for negative history, got %v", err)
	}
}

func TestServiceRunRepoScanLocked(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	locker := scheduler.NewInMemoryLocker()
	release, ok := locker.TryAcquire("identrail:repo-scan:owner/repo")
	if !ok {
		t.Fatal("expected repo lock acquire")
	}
	defer release()
	svc.Locker = locker

	if _, err := svc.RunRepoScanPersisted(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo"}); !errors.Is(err, ErrRepoScanInProgress) {
		t.Fatalf("expected repo scan in progress error, got %v", err)
	}
}

func TestServiceListFindingsWrapperAndRepoScanDetailGuard(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 17, 15, 10, 0, 0, time.UTC)
	scan, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := store.UpsertFindings(defaultScopeContext(), scan.ID, []domain.Finding{
		{ID: "f1", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now},
	}); err != nil {
		t.Fatalf("upsert findings: %v", err)
	}
	svc := NewService(store, fakeScanner{}, "aws")
	items, err := svc.ListFindings(defaultScopeContext(), 10)
	if err != nil {
		t.Fatalf("list findings wrapper: %v", err)
	}
	if len(items) != 1 || items[0].ID != "f1" {
		t.Fatalf("unexpected list findings result %+v", items)
	}
	if _, err := svc.GetRepoScan(defaultScopeContext(), " "); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected not found for empty repo scan id, got %v", err)
	}
}

func TestServiceRunRepoScanPersistedScannerError(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/repo"}
	svc.RepoScannerFactory = func(int, int) RepoScanExecutor {
		return &fakeRepoExecutor{err: errors.New("scanner failed")}
	}
	if _, err := svc.RunRepoScanPersisted(defaultScopeContext(), RepoScanRequest{
		Repository: "owner/repo",
	}); err == nil {
		t.Fatal("expected scanner error")
	}
	repoScans, err := svc.ListRepoScans(defaultScopeContext(), 10)
	if err != nil {
		t.Fatalf("list repo scans: %v", err)
	}
	if len(repoScans) != 1 || repoScans[0].Status != "failed" {
		t.Fatalf("expected failed repo scan record, got %+v", repoScans)
	}
}

func TestServiceEnqueueScanAndProcessQueue(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 20, 8, 0, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{result: app.ScanResult{
		Assets:   2,
		Findings: []domain.Finding{{ID: "f-1", Type: domain.FindingOwnerless, Severity: domain.SeverityHigh, CreatedAt: now}},
	}}, "aws")
	svc.Now = func() time.Time { return now }

	record, err := svc.EnqueueScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("enqueue scan: %v", err)
	}
	if record.Status != "queued" {
		t.Fatalf("expected queued status, got %q", record.Status)
	}
	processed, err := svc.ProcessNextQueuedScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("process queued scan: %v", err)
	}
	if !processed {
		t.Fatal("expected one queued scan to be processed")
	}
	scan, err := store.GetScan(defaultScopeContext(), record.ID)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if scan.Status != "completed" || scan.FindingCount != 1 {
		t.Fatalf("unexpected processed scan record: %+v", scan)
	}
	processed, err = svc.ProcessNextQueuedScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("process queued scan again: %v", err)
	}
	if processed {
		t.Fatal("expected no more queued scans")
	}
}

func TestServiceEnqueueScanQueueFull(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{}, "aws")
	svc.ScanQueueMaxPending = 1
	if _, err := svc.EnqueueScan(defaultScopeContext()); err != nil {
		t.Fatalf("enqueue first scan: %v", err)
	}
	if _, err := svc.EnqueueScan(defaultScopeContext()); !errors.Is(err, ErrScanQueueFull) {
		t.Fatalf("expected scan queue full error, got %v", err)
	}
}

func TestServiceQueuedScanBurstProcessing(t *testing.T) {
	store := db.NewMemoryStore()
	now := time.Date(2026, 3, 20, 8, 15, 0, 0, time.UTC)
	svc := NewService(store, fakeScanner{result: app.ScanResult{
		Assets:   1,
		Findings: []domain.Finding{{ID: "f-burst", Type: domain.FindingOwnerless, Severity: domain.SeverityLow, CreatedAt: now}},
	}}, "aws")
	svc.Now = func() time.Time { return now }
	svc.ScanQueueMaxPending = 100

	const queued = 40
	for i := 0; i < queued; i++ {
		if _, err := svc.EnqueueScan(defaultScopeContext()); err != nil {
			t.Fatalf("enqueue burst scan %d: %v", i, err)
		}
	}
	processedCount := 0
	for {
		processed, err := svc.ProcessNextQueuedScan(defaultScopeContext())
		if err != nil {
			t.Fatalf("process burst queue: %v", err)
		}
		if !processed {
			break
		}
		processedCount++
	}
	if processedCount != queued {
		t.Fatalf("expected %d processed scans, got %d", queued, processedCount)
	}
	scans, err := store.ListScans(defaultScopeContext(), 1000)
	if err != nil {
		t.Fatalf("list scans: %v", err)
	}
	if len(scans) != queued {
		t.Fatalf("expected %d persisted scans, got %d", queued, len(scans))
	}
	for _, scan := range scans {
		if scan.Status != "completed" {
			t.Fatalf("expected completed scan status, got %q", scan.Status)
		}
	}
}

func TestServiceEnqueueRepoScanAndProcessQueue(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	svc.RepoQueueMaxPending = 2
	svc.RepoScannerFactory = func(historyLimit int, maxFindings int) RepoScanExecutor {
		return &fakeRepoExecutor{
			result: repoexposure.ScanResult{
				Repository:     "owner/repo",
				CommitsScanned: historyLimit,
				FilesScanned:   6,
				Findings: []domain.Finding{
					{ID: "rf-queued", Type: domain.FindingSecretExposure, Severity: domain.SeverityHigh, CreatedAt: time.Now().UTC()},
				},
				Truncated: false,
			},
		}
	}
	record, err := svc.EnqueueRepoScan(defaultScopeContext(), RepoScanRequest{
		Repository:   "owner/repo",
		HistoryLimit: 25,
		MaxFindings:  30,
	})
	if err != nil {
		t.Fatalf("enqueue repo scan: %v", err)
	}
	if record.Status != "queued" {
		t.Fatalf("expected queued repo scan status, got %q", record.Status)
	}
	processed, err := svc.ProcessNextQueuedRepoScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("process queued repo scan: %v", err)
	}
	if !processed {
		t.Fatal("expected queued repo scan to be processed")
	}
	stored, err := svc.GetRepoScan(defaultScopeContext(), record.ID)
	if err != nil {
		t.Fatalf("get repo scan: %v", err)
	}
	if stored.Status != "completed" || stored.CommitsScanned != 25 {
		t.Fatalf("unexpected processed repo scan record: %+v", stored)
	}
}

func TestServiceEnqueueRepoScanGuards(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	svc.RepoQueueMaxPending = 1

	if _, err := svc.EnqueueRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo"}); err != nil {
		t.Fatalf("enqueue first repo scan: %v", err)
	}
	if _, err := svc.EnqueueRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo"}); !errors.Is(err, ErrRepoScanInProgress) {
		t.Fatalf("expected repo in-progress error for duplicate target, got %v", err)
	}
	if _, err := svc.EnqueueRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "Owner/Repo"}); !errors.Is(err, ErrRepoScanInProgress) {
		t.Fatalf("expected repo in-progress error for case-variant duplicate target, got %v", err)
	}
	if _, err := svc.EnqueueRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/another"}); !errors.Is(err, ErrRepoScanQueueFull) {
		t.Fatalf("expected repo queue full error, got %v", err)
	}
}

func TestServiceProcessQueuedRepoScanRequeuesWhenExecutionLockHeld(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	queuedAt := time.Date(2026, 3, 24, 10, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return queuedAt }

	record, err := svc.EnqueueRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo"})
	if err != nil {
		t.Fatalf("enqueue repo scan: %v", err)
	}
	locker := scheduler.NewInMemoryLocker()
	release, ok := locker.TryAcquire("identrail:repo-scan:owner/repo")
	if !ok {
		t.Fatal("expected lock acquire")
	}
	defer release()
	svc.Locker = locker

	processed, err := svc.ProcessNextQueuedRepoScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("process queued repo scan: %v", err)
	}
	if !processed {
		t.Fatal("expected requeue handling to count as queue progress")
	}
	stored, err := svc.GetRepoScan(defaultScopeContext(), record.ID)
	if err != nil {
		t.Fatalf("get repo scan: %v", err)
	}
	if stored.Status != "queued" {
		t.Fatalf("expected repo scan to be requeued, got status %q", stored.Status)
	}
	if !stored.StartedAt.After(queuedAt) {
		t.Fatalf("expected requeued repo scan to move to the back of the queue")
	}
}

func TestServiceProcessQueuedRepoScanContinuesToNextTargetAfterRequeue(t *testing.T) {
	store := db.NewMemoryStore()
	svc := NewService(store, fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"owner/*"}
	now := time.Date(2026, 3, 24, 11, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }
	svc.RepoScannerFactory = func(historyLimit int, maxFindings int) RepoScanExecutor {
		return &fakeRepoExecutor{
			result: repoexposure.ScanResult{
				Repository:     "owner/repo-b",
				CommitsScanned: historyLimit,
				FilesScanned:   2,
				Findings: []domain.Finding{
					{ID: "rf-next", Type: domain.FindingSecretExposure, Severity: domain.SeverityHigh, CreatedAt: now},
				},
			},
		}
	}

	repoA, err := svc.EnqueueRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo-a"})
	if err != nil {
		t.Fatalf("enqueue repo-a scan: %v", err)
	}
	repoB, err := svc.EnqueueRepoScan(defaultScopeContext(), RepoScanRequest{Repository: "owner/repo-b"})
	if err != nil {
		t.Fatalf("enqueue repo-b scan: %v", err)
	}

	locker := scheduler.NewInMemoryLocker()
	release, ok := locker.TryAcquire("identrail:repo-scan:owner/repo-a")
	if !ok {
		t.Fatal("expected lock acquire")
	}
	defer release()
	svc.Locker = locker

	processed, err := svc.ProcessNextQueuedRepoScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("first queue process failed: %v", err)
	}
	if !processed {
		t.Fatal("expected first queue pass to requeue locked target")
	}

	processed, err = svc.ProcessNextQueuedRepoScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("second queue process failed: %v", err)
	}
	if !processed {
		t.Fatal("expected second queue pass to process next target")
	}

	repoARecord, err := svc.GetRepoScan(defaultScopeContext(), repoA.ID)
	if err != nil {
		t.Fatalf("get repo-a scan: %v", err)
	}
	if repoARecord.Status != "queued" {
		t.Fatalf("expected repo-a to remain queued while lock is held, got %q", repoARecord.Status)
	}

	repoBRecord, err := svc.GetRepoScan(defaultScopeContext(), repoB.ID)
	if err != nil {
		t.Fatalf("get repo-b scan: %v", err)
	}
	if repoBRecord.Status != "completed" {
		t.Fatalf("expected repo-b to complete, got %q", repoBRecord.Status)
	}
}

func TestRepoTargetAllowed(t *testing.T) {
	if repoTargetAllowed("owner/repo", nil) {
		t.Fatal("expected empty allowlist to deny target")
	}
	if !repoTargetAllowed("trusted/team-repo", []string{"trusted/*"}) {
		t.Fatal("expected wildcard allowlist to allow target")
	}
	if repoTargetAllowed("owner/repo", []string{"trusted/*"}) {
		t.Fatal("expected disallowed target")
	}
}

func TestServiceRunRepoScanRejectsLocalRepositoryTarget(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{}, "aws")
	svc.RepoScanAllowedTargets = []string{"*"}

	repo := t.TempDir()
	if output, err := exec.Command("git", "init", "--quiet", repo).CombinedOutput(); err != nil {
		t.Fatalf("prepare local repo fixture: %v (%s)", err, string(output))
	}

	if _, err := svc.RunRepoScan(defaultScopeContext(), RepoScanRequest{Repository: repo}); !errors.Is(err, ErrRepoTargetNotAllowed) {
		t.Fatalf("expected local repo target rejection, got %v", err)
	}
}

func TestSanitizeRepoScanLimit(t *testing.T) {
	got, err := sanitizeRepoScanLimit(0, 100, 500)
	if err != nil || got != 100 {
		t.Fatalf("expected fallback 100, got=%d err=%v", got, err)
	}
	if _, err := sanitizeRepoScanLimit(-1, 100, 500); !errors.Is(err, ErrInvalidRepoScanRequest) {
		t.Fatalf("expected invalid error for negative value, got %v", err)
	}
	if _, err := sanitizeRepoScanLimit(600, 100, 500); !errors.Is(err, ErrInvalidRepoScanRequest) {
		t.Fatalf("expected invalid error for over max value, got %v", err)
	}
}

func TestServiceLockKeyNamespace(t *testing.T) {
	svc := NewService(db.NewMemoryStore(), fakeScanner{}, "aws")
	if got := svc.lockKey("scan:aws"); got != "identrail:scan:aws" {
		t.Fatalf("unexpected default namespaced lock key %q", got)
	}
	svc.LockNamespace = ""
	if got := svc.lockKey("scan:aws"); got != "scan:aws" {
		t.Fatalf("unexpected lock key without namespace %q", got)
	}
}
