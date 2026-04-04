package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

func TestMemoryStoreScanLifecycleAndFindings(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	scan, err := store.CreateScan(defaultScopeContext(), "aws", now)
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
	if err := store.UpsertFindings(defaultScopeContext(), scan.ID, findings); err != nil {
		t.Fatalf("upsert findings failed: %v", err)
	}
	if err := store.UpsertArtifacts(defaultScopeContext(), scan.ID, ScanArtifacts{
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
	if err := store.UpsertArtifacts(defaultScopeContext(), scan.ID, ScanArtifacts{}); err != nil {
		t.Fatalf("second upsert artifacts failed: %v", err)
	}

	if err := store.CompleteScan(defaultScopeContext(), scan.ID, "completed", now.Add(2*time.Second), 3, 1, ""); err != nil {
		t.Fatalf("complete scan failed: %v", err)
	}

	scans, err := store.ListScans(defaultScopeContext(), 10)
	if err != nil {
		t.Fatalf("list scans failed: %v", err)
	}
	if len(scans) != 1 || scans[0].Status != "completed" || scans[0].FindingCount != 1 {
		t.Fatalf("unexpected scans: %+v", scans)
	}

	storedFindings, err := store.ListFindings(defaultScopeContext(), 10)
	if err != nil {
		t.Fatalf("list findings failed: %v", err)
	}
	if len(storedFindings) != 1 || storedFindings[0].ScanID != scan.ID {
		t.Fatalf("unexpected findings: %+v", storedFindings)
	}
}

func TestMemoryStoreErrorsForUnknownScan(t *testing.T) {
	store := NewMemoryStore()
	err := store.CompleteScan(defaultScopeContext(), "missing", "failed", time.Now(), 0, 0, "boom")
	if err == nil {
		t.Fatal("expected error")
	}

	err = store.UpsertFindings(defaultScopeContext(), "missing", []domain.Finding{{ID: "f1"}})
	if err == nil {
		t.Fatal("expected error")
	}
	err = store.UpsertArtifacts(defaultScopeContext(), "missing", ScanArtifacts{})
	if err == nil {
		t.Fatal("expected error")
	}
	_, err = store.GetScan(defaultScopeContext(), "missing")
	if err == nil {
		t.Fatal("expected get scan error")
	}
	_, err = store.ListFindingsByScan(defaultScopeContext(), "missing", 10)
	if err == nil {
		t.Fatal("expected findings-by-scan error")
	}
	err = store.AppendScanEvent(defaultScopeContext(), "missing", "info", "msg", nil)
	if err == nil {
		t.Fatal("expected append scan event error")
	}
	_, err = store.ListScanEvents(defaultScopeContext(), "missing", 10)
	if err == nil {
		t.Fatal("expected list scan events error")
	}
}

func TestMemoryStoreScanDetails(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)

	scanA, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan A: %v", err)
	}
	scanB, err := store.CreateScan(defaultScopeContext(), "aws", now.Add(1*time.Minute))
	if err != nil {
		t.Fatalf("create scan B: %v", err)
	}

	if err := store.UpsertFindings(defaultScopeContext(), scanA.ID, []domain.Finding{
		{ID: "f1", ScanID: scanA.ID, CreatedAt: now.Add(1 * time.Second)},
		{ID: "f2", ScanID: scanA.ID, CreatedAt: now.Add(2 * time.Second)},
	}); err != nil {
		t.Fatalf("upsert findings: %v", err)
	}

	gotScan, err := store.GetScan(defaultScopeContext(), scanA.ID)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if gotScan.ID != scanA.ID {
		t.Fatalf("unexpected scan id: %q", gotScan.ID)
	}

	findings, err := store.ListFindingsByScan(defaultScopeContext(), scanA.ID, 10)
	if err != nil {
		t.Fatalf("list findings by scan: %v", err)
	}
	if len(findings) != 2 || findings[0].ID != "f2" {
		t.Fatalf("unexpected findings: %+v", findings)
	}

	if err := store.AppendScanEvent(defaultScopeContext(), scanB.ID, "info", "scan started", map[string]any{"provider": "aws"}); err != nil {
		t.Fatalf("append scan event 1: %v", err)
	}
	if err := store.AppendScanEvent(defaultScopeContext(), scanB.ID, "info", "scan completed", nil); err != nil {
		t.Fatalf("append scan event 2: %v", err)
	}
	events, err := store.ListScanEvents(defaultScopeContext(), scanB.ID, 10)
	if err != nil {
		t.Fatalf("list scan events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
}

func TestMemoryStoreIdentityAndRelationshipFilters(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	scanA, err := store.CreateScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create scan A: %v", err)
	}
	scanB, err := store.CreateScan(defaultScopeContext(), "aws", now.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("create scan B: %v", err)
	}
	if err := store.UpsertArtifacts(defaultScopeContext(), scanA.ID, ScanArtifacts{
		Bundle: providers.NormalizedBundle{
			Identities: []domain.Identity{
				{ID: "id-1", Provider: domain.ProviderAWS, Type: domain.IdentityTypeRole, Name: "app-role", RawRef: "raw-1"},
				{ID: "id-2", Provider: domain.ProviderAWS, Type: domain.IdentityTypeRole, Name: "db-role", RawRef: "raw-2"},
			},
		},
		Relationships: []domain.Relationship{
			{ID: "rel-1", Type: domain.RelationshipCanAssume, FromNodeID: "id-1", ToNodeID: "id-2", DiscoveredAt: now},
		},
	}); err != nil {
		t.Fatalf("upsert artifacts scan A: %v", err)
	}
	if err := store.UpsertArtifacts(defaultScopeContext(), scanB.ID, ScanArtifacts{
		Bundle: providers.NormalizedBundle{
			Identities: []domain.Identity{
				{ID: "id-3", Provider: domain.ProviderAWS, Type: domain.IdentityTypeRole, Name: "app-worker", RawRef: "raw-3"},
			},
		},
		Relationships: []domain.Relationship{
			{ID: "rel-2", Type: domain.RelationshipCanAccess, FromNodeID: "id-3", ToNodeID: "bucket-1", DiscoveredAt: now.Add(1 * time.Minute)},
		},
	}); err != nil {
		t.Fatalf("upsert artifacts scan B: %v", err)
	}

	identities, err := store.ListIdentities(defaultScopeContext(), IdentityFilter{ScanID: scanA.ID, NamePrefix: "app"}, 10)
	if err != nil {
		t.Fatalf("list identities: %v", err)
	}
	if len(identities) != 1 || identities[0].ID != "id-1" {
		t.Fatalf("unexpected identities: %+v", identities)
	}

	relationships, err := store.ListRelationships(defaultScopeContext(), RelationshipFilter{Type: "can_access"}, 10)
	if err != nil {
		t.Fatalf("list relationships: %v", err)
	}
	if len(relationships) != 1 || relationships[0].ID != "rel-2" {
		t.Fatalf("unexpected relationships: %+v", relationships)
	}
}

func TestMemoryStoreRejectsInvalidScanEventLevel(t *testing.T) {
	store := NewMemoryStore()
	scan, err := store.CreateScan(defaultScopeContext(), "aws", time.Now().UTC())
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	err = store.AppendScanEvent(defaultScopeContext(), scan.ID, "invalid", "bad level", nil)
	if err == nil {
		t.Fatal("expected invalid event level error")
	}
}

func TestMemoryStoreRepoScanLifecycle(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 17, 14, 0, 0, 0, time.UTC)

	repoScan, err := store.CreateRepoScan(defaultScopeContext(), "owner/repo", now)
	if err != nil {
		t.Fatalf("create repo scan: %v", err)
	}
	if repoScan.Status != "running" {
		t.Fatalf("unexpected repo scan status %q", repoScan.Status)
	}

	findings := []domain.Finding{
		{ID: "rf-1", Type: domain.FindingSecretExposure, Severity: domain.SeverityHigh, Title: "secret", HumanSummary: "summary", CreatedAt: now},
		{ID: "rf-2", Type: domain.FindingRepoMisconfig, Severity: domain.SeverityMedium, Title: "misconfig", HumanSummary: "summary", CreatedAt: now.Add(1 * time.Minute)},
	}
	if err := store.UpsertRepoFindings(defaultScopeContext(), repoScan.ID, findings); err != nil {
		t.Fatalf("upsert repo findings: %v", err)
	}
	if err := store.CompleteRepoScan(defaultScopeContext(), repoScan.ID, "completed", now.Add(2*time.Minute), 10, 6, 2, false, ""); err != nil {
		t.Fatalf("complete repo scan: %v", err)
	}

	gotScan, err := store.GetRepoScan(defaultScopeContext(), repoScan.ID)
	if err != nil {
		t.Fatalf("get repo scan: %v", err)
	}
	if gotScan.Status != "completed" || gotScan.CommitsScanned != 10 || gotScan.FilesScanned != 6 || gotScan.FindingCount != 2 {
		t.Fatalf("unexpected repo scan record: %+v", gotScan)
	}

	storedFindings, err := store.ListRepoFindings(defaultScopeContext(), RepoFindingFilter{RepoScanID: repoScan.ID}, 10)
	if err != nil {
		t.Fatalf("list repo findings: %v", err)
	}
	if len(storedFindings) != 2 || storedFindings[0].ID != "rf-2" {
		t.Fatalf("unexpected repo findings: %+v", storedFindings)
	}

	highOnly, err := store.ListRepoFindings(defaultScopeContext(), RepoFindingFilter{Severity: "high"}, 10)
	if err != nil {
		t.Fatalf("list repo findings high-only: %v", err)
	}
	if len(highOnly) != 1 || highOnly[0].ID != "rf-1" {
		t.Fatalf("unexpected high severity findings: %+v", highOnly)
	}

	repoScans, err := store.ListRepoScans(defaultScopeContext(), 10)
	if err != nil {
		t.Fatalf("list repo scans: %v", err)
	}
	if len(repoScans) != 1 || repoScans[0].ID != repoScan.ID {
		t.Fatalf("unexpected repo scans: %+v", repoScans)
	}
}

func TestMemoryStoreRepoScanErrors(t *testing.T) {
	store := NewMemoryStore()
	if _, err := store.GetRepoScan(defaultScopeContext(), "missing"); err == nil {
		t.Fatal("expected missing repo scan error")
	}
	if err := store.UpsertRepoFindings(defaultScopeContext(), "missing", []domain.Finding{{ID: "x"}}); err == nil {
		t.Fatal("expected missing repo scan error for findings upsert")
	}
	if err := store.CompleteRepoScan(defaultScopeContext(), "missing", "failed", time.Now(), 0, 0, 0, false, "boom"); err == nil {
		t.Fatal("expected missing repo scan error for completion")
	}
	if _, err := store.ListRepoFindings(defaultScopeContext(), RepoFindingFilter{RepoScanID: "missing"}, 10); err == nil {
		t.Fatal("expected missing repo scan error for findings list")
	}
}

func TestMemoryStoreFindingTriageStateAndHistory(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 28, 9, 0, 0, 0, time.UTC)
	expiry := now.Add(24 * time.Hour)

	if _, err := store.GetFindingTriageState(defaultScopeContext(), "finding-1"); err == nil {
		t.Fatal("expected missing triage state error")
	}

	state := FindingTriageState{
		FindingID:            "finding-1",
		Status:               domain.FindingLifecycleSuppressed,
		Assignee:             "sec-oncall",
		SuppressionExpiresAt: &expiry,
		UpdatedAt:            now,
		UpdatedBy:            "subject:alice",
	}
	if err := store.UpsertFindingTriageState(defaultScopeContext(), state); err != nil {
		t.Fatalf("upsert triage state: %v", err)
	}
	gotState, err := store.GetFindingTriageState(defaultScopeContext(), "finding-1")
	if err != nil {
		t.Fatalf("get triage state: %v", err)
	}
	if gotState.Status != domain.FindingLifecycleSuppressed || gotState.Assignee != "sec-oncall" {
		t.Fatalf("unexpected triage state: %+v", gotState)
	}

	states, err := store.ListFindingTriageStates(defaultScopeContext(), []string{"finding-1", "missing"})
	if err != nil {
		t.Fatalf("list triage states: %v", err)
	}
	if len(states) != 1 || states[0].FindingID != "finding-1" {
		t.Fatalf("unexpected triage states: %+v", states)
	}

	firstEvent := FindingTriageEvent{
		FindingID:  "finding-1",
		Action:     FindingTriageActionSuppressed,
		FromStatus: domain.FindingLifecycleOpen,
		ToStatus:   domain.FindingLifecycleSuppressed,
		Assignee:   "sec-oncall",
		Comment:    "temporary exception",
		Actor:      "subject:alice",
		CreatedAt:  now,
	}
	secondEvent := FindingTriageEvent{
		FindingID:  "finding-1",
		Action:     FindingTriageActionCommented,
		FromStatus: domain.FindingLifecycleSuppressed,
		ToStatus:   domain.FindingLifecycleSuppressed,
		Comment:    "reviewed",
		Actor:      "subject:bob",
		CreatedAt:  now.Add(1 * time.Minute),
	}
	if err := store.AppendFindingTriageEvent(defaultScopeContext(), firstEvent); err != nil {
		t.Fatalf("append first triage event: %v", err)
	}
	if err := store.AppendFindingTriageEvent(defaultScopeContext(), secondEvent); err != nil {
		t.Fatalf("append second triage event: %v", err)
	}
	events, err := store.ListFindingTriageEvents(defaultScopeContext(), "finding-1", 10)
	if err != nil {
		t.Fatalf("list triage events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 triage events, got %d", len(events))
	}
	if events[0].Action != FindingTriageActionCommented {
		t.Fatalf("expected latest event first, got %+v", events)
	}
}

func TestMemoryStoreApplyFindingTriageTransitionAtomic(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC)

	err := store.ApplyFindingTriageTransition(defaultScopeContext(), FindingTriageState{
		FindingID: "finding-1",
		Status:    domain.FindingLifecycleAck,
		UpdatedAt: now,
		UpdatedBy: "subject:alice",
	}, FindingTriageEvent{
		FindingID:  "finding-2",
		Action:     FindingTriageActionAcknowledged,
		FromStatus: domain.FindingLifecycleOpen,
		ToStatus:   domain.FindingLifecycleAck,
		CreatedAt:  now,
	})
	if err == nil {
		t.Fatal("expected mismatch error for triage transition")
	}
	if _, err := store.GetFindingTriageState(defaultScopeContext(), "finding-1"); err == nil {
		t.Fatal("expected no state to be persisted after failed transition")
	}
	events, err := store.ListFindingTriageEvents(defaultScopeContext(), "finding-1", 10)
	if err != nil {
		t.Fatalf("list triage events after failed transition: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected no events to be persisted after failed transition, got %d", len(events))
	}
}

func TestMemoryStoreScanQueueLifecycle(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 21, 9, 0, 0, 0, time.UTC)
	queued, err := store.CreateQueuedScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create queued scan: %v", err)
	}
	if queued.Status != "queued" {
		t.Fatalf("expected queued status, got %q", queued.Status)
	}
	count, err := store.CountQueuedScans(defaultScopeContext(), "aws")
	if err != nil {
		t.Fatalf("count queued scans: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected queued count 1, got %d", count)
	}
	claimed, err := store.ClaimNextQueuedScan(defaultScopeContext(), "aws")
	if err != nil {
		t.Fatalf("claim queued scan: %v", err)
	}
	if claimed.ID != queued.ID || claimed.Status != "running" {
		t.Fatalf("unexpected claimed scan %+v", claimed)
	}
	if _, err := store.ClaimNextQueuedScan(defaultScopeContext(), "aws"); err == nil {
		t.Fatal("expected no queued scan remaining")
	}
}

func TestMemoryStoreRepoQueueLifecycle(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 21, 9, 5, 0, 0, time.UTC)
	queued, err := store.CreateQueuedRepoScan(defaultScopeContext(), "owner/repo", 50, 80, now)
	if err != nil {
		t.Fatalf("create queued repo scan: %v", err)
	}
	if queued.Status != "queued" {
		t.Fatalf("expected queued status, got %q", queued.Status)
	}
	if queued.HistoryLimit != 50 || queued.MaxFindings != 80 {
		t.Fatalf("expected queued limits retained, got %+v", queued)
	}
	queuedCount, err := store.CountQueuedRepoScans(defaultScopeContext())
	if err != nil {
		t.Fatalf("count queued repo scans: %v", err)
	}
	if queuedCount != 1 {
		t.Fatalf("expected queued repo count 1, got %d", queuedCount)
	}
	pendingCount, err := store.CountPendingRepoScansByRepository(defaultScopeContext(), "owner/repo")
	if err != nil {
		t.Fatalf("count pending repo scans: %v", err)
	}
	if pendingCount != 1 {
		t.Fatalf("expected pending repo count 1, got %d", pendingCount)
	}
	if err := store.RequeueRepoScan(defaultScopeContext(), queued.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected requeue to reject non-running record, got %v", err)
	}
	claimed, err := store.ClaimNextQueuedRepoScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("claim queued repo scan: %v", err)
	}
	if claimed.ID != queued.ID || claimed.Status != "running" {
		t.Fatalf("unexpected claimed repo scan %+v", claimed)
	}
	if err := store.RequeueRepoScan(defaultScopeContext(), claimed.ID); err != nil {
		t.Fatalf("requeue repo scan: %v", err)
	}
	requeued, err := store.GetRepoScan(defaultScopeContext(), claimed.ID)
	if err != nil {
		t.Fatalf("get requeued repo scan: %v", err)
	}
	if requeued.Status != "queued" {
		t.Fatalf("expected requeued status, got %q", requeued.Status)
	}
	if !requeued.StartedAt.After(claimed.StartedAt) {
		t.Fatal("expected requeued repo scan to receive a fresh queue timestamp")
	}
}

func TestMemoryStorePendingRepoCountMatchingIsCaseInsensitive(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 21, 9, 25, 0, 0, time.UTC)
	if _, err := store.CreateQueuedRepoScan(defaultScopeContext(), "Owner/Repo", 10, 20, now); err != nil {
		t.Fatalf("create queued repo scan: %v", err)
	}

	count, err := store.CountPendingRepoScansByRepository(defaultScopeContext(), "owner/repo")
	if err != nil {
		t.Fatalf("count pending repo scans: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 pending repo scan for case-insensitive repository match, got %d", count)
	}
}

func TestMemoryStoreScopeIsolation(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 3, 22, 10, 0, 0, 0, time.UTC)

	defaultCtx := defaultScopeContext()
	otherCtx := WithScope(defaultScopeContext(), Scope{TenantID: "tenant-b", WorkspaceID: "workspace-b"})

	defaultScan, err := store.CreateScan(defaultCtx, "aws", now)
	if err != nil {
		t.Fatalf("create default scan: %v", err)
	}
	otherScan, err := store.CreateScan(otherCtx, "aws", now.Add(1*time.Minute))
	if err != nil {
		t.Fatalf("create other scan: %v", err)
	}

	if _, err := store.GetScan(defaultCtx, otherScan.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected cross-scope get scan to fail with not found, got %v", err)
	}
	if _, err := store.GetScan(otherCtx, defaultScan.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected cross-scope get scan to fail with not found, got %v", err)
	}

	defaultScans, err := store.ListScans(defaultCtx, 10)
	if err != nil {
		t.Fatalf("list default scans: %v", err)
	}
	if len(defaultScans) != 1 || defaultScans[0].ID != defaultScan.ID {
		t.Fatalf("unexpected default scope scans: %+v", defaultScans)
	}

	otherScans, err := store.ListScans(otherCtx, 10)
	if err != nil {
		t.Fatalf("list other scans: %v", err)
	}
	if len(otherScans) != 1 || otherScans[0].ID != otherScan.ID {
		t.Fatalf("unexpected other scope scans: %+v", otherScans)
	}

	defaultRepo, err := store.CreateQueuedRepoScan(defaultCtx, "owner/repo", 10, 10, now)
	if err != nil {
		t.Fatalf("create default repo scan: %v", err)
	}
	otherRepo, err := store.CreateQueuedRepoScan(otherCtx, "owner/repo", 10, 10, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("create other repo scan: %v", err)
	}

	if _, err := store.GetRepoScan(defaultCtx, otherRepo.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected cross-scope get repo scan to fail with not found, got %v", err)
	}
	if _, err := store.GetRepoScan(otherCtx, defaultRepo.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected cross-scope get repo scan to fail with not found, got %v", err)
	}
}

func TestMemoryStoreRequiresScopeContext(t *testing.T) {
	store := NewMemoryStore()
	if _, err := store.ListScans(context.Background(), 10); !errors.Is(err, ErrScopeRequired) {
		t.Fatalf("expected ErrScopeRequired, got %v", err)
	}
}
