package db

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

func TestPostgresStoreCreateAndCompleteScan(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO scans (id, tenant_id, workspace_id, provider, status, started_at, asset_count, finding_count) VALUES ($1, $2, $3, $4, $5, $6, 0, 0)`)).
		WithArgs(sqlmock.AnyArg(), "default", "default", "aws", "running", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	scan, err := store.CreateScan(defaultScopeContext(), "aws", time.Now())
	if err != nil {
		t.Fatalf("create scan failed: %v", err)
	}

	mock.ExpectExec(regexp.QuoteMeta(`UPDATE scans
		 SET status=$2, finished_at=$3, asset_count=$4, finding_count=$5, error_message=$6
		 WHERE id=$1
		   AND tenant_id=$7
		   AND workspace_id=$8`)).
		WithArgs(scan.ID, "completed", sqlmock.AnyArg(), 2, 1, nil, "default", "default").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.CompleteScan(defaultScopeContext(), scan.ID, "completed", time.Now(), 2, 1, ""); err != nil {
		t.Fatalf("complete scan failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreUpsertFindings(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS (
			SELECT 1
			FROM scans
			WHERE id = $1
			  AND tenant_id = $2
			  AND workspace_id = $3
		)`)).
		WithArgs("scan-1", "default", "default").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO findings").
		WithArgs("scan-1", "f1", "risky_trust_policy", "high", "Risky trust", "summary", sqlmock.AnyArg(), sqlmock.AnyArg(), "fix", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	findings := []domain.Finding{{
		ID:           "f1",
		Type:         domain.FindingRiskyTrustPolicy,
		Severity:     domain.SeverityHigh,
		Title:        "Risky trust",
		HumanSummary: "summary",
		Path:         []string{"a", "b"},
		Evidence:     map[string]any{"k": "v"},
		Remediation:  "fix",
		CreatedAt:    time.Now(),
	}}

	if err := store.UpsertFindings(defaultScopeContext(), "scan-1", findings); err != nil {
		t.Fatalf("upsert findings failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreUpsertArtifacts(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS (
			SELECT 1
			FROM scans
			WHERE id = $1
			  AND tenant_id = $2
			  AND workspace_id = $3
		)`)).
		WithArgs("scan-1", "default", "default").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO raw_assets").WithArgs("scan-1", "arn:aws:iam::1:role/test", "iam_role", sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO identities").WithArgs("scan-1", "aws:identity:arn:aws:iam::1:role/test", "aws", "role", "test", nil, nil, nil, nil, sqlmock.AnyArg(), "raw").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO policies").WithArgs("scan-1", "p1", "aws", "policy", "{}", sqlmock.AnyArg(), "raw").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO relationships").WithArgs("scan-1", "rel-1", "can_access", "a", "b", nil, sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO permissions").WithArgs("scan-1", "a", "s3:GetObject", "*", "Allow").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = store.UpsertArtifacts(defaultScopeContext(), "scan-1", ScanArtifacts{
		RawAssets: []providers.RawAsset{{
			Kind:      "iam_role",
			SourceID:  "arn:aws:iam::1:role/test",
			Payload:   []byte(`{"arn":"arn:aws:iam::1:role/test"}`),
			Collected: now.Format(time.RFC3339Nano),
		}},
		Bundle: providers.NormalizedBundle{
			Identities: []domain.Identity{{ID: "aws:identity:arn:aws:iam::1:role/test", Provider: domain.ProviderAWS, Type: domain.IdentityTypeRole, Name: "test", RawRef: "raw"}},
			Policies:   []domain.Policy{{ID: "p1", Provider: domain.ProviderAWS, Name: "policy", Document: []byte("{}"), Normalized: map[string]any{"k": "v"}, RawRef: "raw"}},
		},
		Relationships: []domain.Relationship{{ID: "rel-1", Type: domain.RelationshipCanAccess, FromNodeID: "a", ToNodeID: "b", DiscoveredAt: now}},
		Permissions:   []providers.PermissionTuple{{IdentityID: "a", Action: "s3:GetObject", Resource: "*", Effect: "Allow"}},
	})
	if err != nil {
		t.Fatalf("upsert artifacts failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreListScansAndFindings(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	scanRows := sqlmock.NewRows([]string{"id", "tenant_id", "workspace_id", "provider", "status", "started_at", "finished_at", "asset_count", "finding_count", "error_message"}).
		AddRow("scan-1", "default", "default", "aws", "completed", now, now, 2, 1, "")
	mock.ExpectQuery("SELECT id, tenant_id, workspace_id, provider, status").WithArgs("default", "default", 20).WillReturnRows(scanRows)

	scans, err := store.ListScans(defaultScopeContext(), 20)
	if err != nil {
		t.Fatalf("list scans failed: %v", err)
	}
	if len(scans) != 1 || scans[0].ID != "scan-1" {
		t.Fatalf("unexpected scans: %+v", scans)
	}

	findingsRows := sqlmock.NewRows([]string{"scan_id", "finding_id", "type", "severity", "title", "human_summary", "path", "evidence", "remediation", "created_at"}).
		AddRow("scan-1", "f1", "ownerless_identity", "medium", "Ownerless", "summary", []byte("[\"x\"]"), []byte("{\"a\":1}"), "fix", now)
	mock.ExpectQuery("SELECT f.scan_id, f.finding_id, f.type").WithArgs("default", "default", 100).WillReturnRows(findingsRows)

	findings, err := store.ListFindings(defaultScopeContext(), 100)
	if err != nil {
		t.Fatalf("list findings failed: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "f1" {
		t.Fatalf("unexpected findings: %+v", findings)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreGetScanAndFindingsByScan(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	scanRow := sqlmock.NewRows([]string{"id", "tenant_id", "workspace_id", "provider", "status", "started_at", "finished_at", "asset_count", "finding_count", "error_message"}).
		AddRow("scan-1", "default", "default", "aws", "completed", now, now, 2, 1, "")
	mock.ExpectQuery("SELECT id, tenant_id, workspace_id, provider, status").WithArgs("scan-1", "default", "default").WillReturnRows(scanRow)

	scan, err := store.GetScan(defaultScopeContext(), "scan-1")
	if err != nil {
		t.Fatalf("get scan failed: %v", err)
	}
	if scan.ID != "scan-1" {
		t.Fatalf("unexpected scan: %+v", scan)
	}

	findingsRows := sqlmock.NewRows([]string{"scan_id", "finding_id", "type", "severity", "title", "human_summary", "path", "evidence", "remediation", "created_at"}).
		AddRow("scan-1", "f1", "ownerless_identity", "medium", "Ownerless", "summary", []byte("[\"x\"]"), []byte("{\"a\":1}"), "fix", now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS (
			SELECT 1
			FROM scans
			WHERE id = $1
			  AND tenant_id = $2
			  AND workspace_id = $3
		)`)).
		WithArgs("scan-1", "default", "default").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("SELECT f.scan_id, f.finding_id, f.type").WithArgs("scan-1", "default", "default", 100).WillReturnRows(findingsRows)

	findings, err := store.ListFindingsByScan(defaultScopeContext(), "scan-1", 100)
	if err != nil {
		t.Fatalf("list findings by scan failed: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "f1" {
		t.Fatalf("unexpected findings: %+v", findings)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreScanEvents(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	mock.ExpectExec("INSERT INTO scan_events").
		WithArgs(sqlmock.AnyArg(), "scan-1", "info", "scan started", sqlmock.AnyArg(), "default", "default").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.AppendScanEvent(defaultScopeContext(), "scan-1", "info", "scan started", map[string]any{"provider": "aws"}); err != nil {
		t.Fatalf("append scan event failed: %v", err)
	}

	now := time.Now().UTC()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS (
			SELECT 1
			FROM scans
			WHERE id = $1
			  AND tenant_id = $2
			  AND workspace_id = $3
		)`)).
		WithArgs("scan-1", "default", "default").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	rows := sqlmock.NewRows([]string{"id", "scan_id", "level", "message", "metadata", "created_at"}).
		AddRow("event-1", "scan-1", "info", "scan started", []byte(`{"provider":"aws"}`), now)
	mock.ExpectQuery("SELECT e.id, e.scan_id, e.level, e.message, e.metadata, e.created_at").WithArgs("scan-1", "default", "default", 10).WillReturnRows(rows)

	events, err := store.ListScanEvents(defaultScopeContext(), "scan-1", 10)
	if err != nil {
		t.Fatalf("list scan events failed: %v", err)
	}
	if len(events) != 1 || events[0].ID != "event-1" {
		t.Fatalf("unexpected events: %+v", events)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreRejectsInvalidScanEventLevel(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	if err := store.AppendScanEvent(defaultScopeContext(), "scan-1", "invalid", "bad", nil); err == nil {
		t.Fatal("expected invalid level error")
	}
}

func TestPostgresStoreListIdentitiesAndRelationships(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	identityRows := sqlmock.NewRows([]string{"id", "provider", "type", "name", "arn", "owner_hint", "created_at", "last_used_at", "tags", "raw_ref"}).
		AddRow("id-1", "aws", "role", "app-role", "arn:aws:iam::1:role/app-role", "", now, nil, []byte(`{"team":"platform"}`), "raw-1")
	mock.ExpectQuery("SELECT i.id, i.provider, i.type, i.name").WithArgs("", "aws", "role", "app", 20, "default", "default").WillReturnRows(identityRows)

	identities, err := store.ListIdentities(defaultScopeContext(), IdentityFilter{
		Provider:   "aws",
		Type:       "role",
		NamePrefix: "app",
	}, 20)
	if err != nil {
		t.Fatalf("list identities failed: %v", err)
	}
	if len(identities) != 1 || identities[0].ID != "id-1" {
		t.Fatalf("unexpected identities: %+v", identities)
	}

	relationshipRows := sqlmock.NewRows([]string{"id", "type", "from_node_id", "to_node_id", "evidence_ref", "discovered_at"}).
		AddRow("rel-1", "can_assume", "id-1", "id-2", "", now)
	mock.ExpectQuery("SELECT r.id, r.type, r.from_node_id").WithArgs("", "can_assume", "", "", 30, "default", "default").WillReturnRows(relationshipRows)

	relationships, err := store.ListRelationships(defaultScopeContext(), RelationshipFilter{Type: "can_assume"}, 30)
	if err != nil {
		t.Fatalf("list relationships failed: %v", err)
	}
	if len(relationships) != 1 || relationships[0].ID != "rel-1" {
		t.Fatalf("unexpected relationships: %+v", relationships)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestNewPostgresStoreWithDB(t *testing.T) {
	store := NewPostgresStoreWithDB(&sql.DB{})
	if store == nil {
		t.Fatal("expected store")
	}
}

func TestPostgresStoreRepoScanLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO repo_scans (id, tenant_id, workspace_id, repository, status, started_at, commits_scanned, files_scanned, finding_count, truncated, history_limit, max_findings_limit)
		 VALUES ($1, $2, $3, $4, $5, $6, 0, 0, 0, false, $7, $8)`)).
		WithArgs(sqlmock.AnyArg(), "default", "default", "owner/repo", "running", sqlmock.AnyArg(), 0, 0).
		WillReturnResult(sqlmock.NewResult(1, 1))

	record, err := store.CreateRepoScan(defaultScopeContext(), "owner/repo", now)
	if err != nil {
		t.Fatalf("create repo scan failed: %v", err)
	}

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS (
			SELECT 1
			FROM repo_scans
			WHERE id = $1
			  AND tenant_id = $2
			  AND workspace_id = $3
		)`)).
		WithArgs(record.ID, "default", "default").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO repo_findings").
		WithArgs(record.ID, "rf-1", "secret_exposure", "high", "secret", "summary", sqlmock.AnyArg(), sqlmock.AnyArg(), "fix", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	if err := store.UpsertRepoFindings(defaultScopeContext(), record.ID, []domain.Finding{{
		ID:           "rf-1",
		Type:         domain.FindingSecretExposure,
		Severity:     domain.SeverityHigh,
		Title:        "secret",
		HumanSummary: "summary",
		Path:         []string{"app.env"},
		Evidence:     map[string]any{"k": "v"},
		Remediation:  "fix",
		CreatedAt:    now,
	}}); err != nil {
		t.Fatalf("upsert repo findings failed: %v", err)
	}

	mock.ExpectExec(regexp.QuoteMeta(`UPDATE repo_scans
		 SET status = $2,
		     finished_at = $3,
		     commits_scanned = $4,
		     files_scanned = $5,
		     finding_count = $6,
		     truncated = $7,
		     error_message = $8
		 WHERE id = $1
		   AND tenant_id = $9
		   AND workspace_id = $10`)).
		WithArgs(record.ID, "completed", sqlmock.AnyArg(), 12, 8, 1, false, nil, "default", "default").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.CompleteRepoScan(defaultScopeContext(), record.ID, "completed", now, 12, 8, 1, false, ""); err != nil {
		t.Fatalf("complete repo scan failed: %v", err)
	}

	repoScanRows := sqlmock.NewRows([]string{"id", "tenant_id", "workspace_id", "repository", "status", "started_at", "finished_at", "commits_scanned", "files_scanned", "finding_count", "truncated", "error_message", "history_limit", "max_findings_limit"}).
		AddRow(record.ID, "default", "default", "owner/repo", "completed", now, now, 12, 8, 1, false, "", 0, 0)
	mock.ExpectQuery("SELECT id, tenant_id, workspace_id, repository, status").WithArgs("default", "default", 20).WillReturnRows(repoScanRows)
	repoScans, err := store.ListRepoScans(defaultScopeContext(), 20)
	if err != nil {
		t.Fatalf("list repo scans failed: %v", err)
	}
	if len(repoScans) != 1 || repoScans[0].ID != record.ID {
		t.Fatalf("unexpected repo scans: %+v", repoScans)
	}

	repoFindingsRows := sqlmock.NewRows([]string{"repo_scan_id", "finding_id", "type", "severity", "title", "human_summary", "path", "evidence", "remediation", "created_at"}).
		AddRow(record.ID, "rf-1", "secret_exposure", "high", "secret", "summary", []byte(`["app.env"]`), []byte(`{"k":"v"}`), "fix", now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT EXISTS (
			SELECT 1
			FROM repo_scans
			WHERE id = $1
			  AND tenant_id = $2
			  AND workspace_id = $3
		)`)).
		WithArgs(record.ID, "default", "default").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery("SELECT rf.repo_scan_id, rf.finding_id, rf.type").WithArgs(record.ID, "", "", 100, "default", "default").WillReturnRows(repoFindingsRows)
	repoFindings, err := store.ListRepoFindings(defaultScopeContext(), RepoFindingFilter{RepoScanID: record.ID}, 100)
	if err != nil {
		t.Fatalf("list repo findings failed: %v", err)
	}
	if len(repoFindings) != 1 || repoFindings[0].ID != "rf-1" {
		t.Fatalf("unexpected repo findings: %+v", repoFindings)
	}

	repoScanRow := sqlmock.NewRows([]string{"id", "tenant_id", "workspace_id", "repository", "status", "started_at", "finished_at", "commits_scanned", "files_scanned", "finding_count", "truncated", "error_message", "history_limit", "max_findings_limit"}).
		AddRow(record.ID, "default", "default", "owner/repo", "completed", now, now, 12, 8, 1, false, "", 0, 0)
	mock.ExpectQuery("SELECT id, tenant_id, workspace_id, repository, status").WithArgs(record.ID, "default", "default").WillReturnRows(repoScanRow)
	gotRepoScan, err := store.GetRepoScan(defaultScopeContext(), record.ID)
	if err != nil {
		t.Fatalf("get repo scan failed: %v", err)
	}
	if gotRepoScan.ID != record.ID {
		t.Fatalf("unexpected repo scan: %+v", gotRepoScan)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreFindingTriageStateAndHistory(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()
	expiry := now.Add(2 * time.Hour)

	mock.ExpectExec("INSERT INTO finding_triage_states").
		WithArgs("default", "default", "finding-1", "ack", "sec-oncall", sqlmock.AnyArg(), sqlmock.AnyArg(), "subject:alice").
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.UpsertFindingTriageState(defaultScopeContext(), FindingTriageState{
		FindingID:            "finding-1",
		Status:               domain.FindingLifecycleAck,
		Assignee:             "sec-oncall",
		SuppressionExpiresAt: &expiry,
		UpdatedAt:            now,
		UpdatedBy:            "subject:alice",
	}); err != nil {
		t.Fatalf("upsert triage state failed: %v", err)
	}

	stateRows := sqlmock.NewRows([]string{"finding_id", "status", "assignee", "suppression_expires_at", "updated_at", "updated_by"}).
		AddRow("finding-1", "ack", "sec-oncall", expiry, now, "subject:alice")
	mock.ExpectQuery("SELECT finding_id, status, assignee, suppression_expires_at, updated_at, updated_by").
		WithArgs("finding-1", "default", "default").
		WillReturnRows(stateRows)

	state, err := store.GetFindingTriageState(defaultScopeContext(), "finding-1")
	if err != nil {
		t.Fatalf("get triage state failed: %v", err)
	}
	if state.Status != domain.FindingLifecycleAck || state.Assignee != "sec-oncall" {
		t.Fatalf("unexpected triage state: %+v", state)
	}

	listRows := sqlmock.NewRows([]string{"finding_id", "status", "assignee", "suppression_expires_at", "updated_at", "updated_by"}).
		AddRow("finding-1", "ack", "sec-oncall", expiry, now, "subject:alice")
	mock.ExpectQuery("SELECT finding_id, status, assignee, suppression_expires_at, updated_at, updated_by").
		WithArgs("default", "default", "finding-1", "finding-2").
		WillReturnRows(listRows)

	states, err := store.ListFindingTriageStates(defaultScopeContext(), []string{"finding-1", "finding-2"})
	if err != nil {
		t.Fatalf("list triage states failed: %v", err)
	}
	if len(states) != 1 || states[0].FindingID != "finding-1" {
		t.Fatalf("unexpected triage states: %+v", states)
	}

	mock.ExpectExec("INSERT INTO finding_triage_events").
		WithArgs(sqlmock.AnyArg(), "default", "default", "finding-1", FindingTriageActionAcknowledged, "open", "ack", "sec-oncall", sqlmock.AnyArg(), "accepted risk", "subject:alice", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.AppendFindingTriageEvent(defaultScopeContext(), FindingTriageEvent{
		FindingID:            "finding-1",
		Action:               FindingTriageActionAcknowledged,
		FromStatus:           domain.FindingLifecycleOpen,
		ToStatus:             domain.FindingLifecycleAck,
		Assignee:             "sec-oncall",
		SuppressionExpiresAt: &expiry,
		Comment:              "accepted risk",
		Actor:                "subject:alice",
		CreatedAt:            now,
	}); err != nil {
		t.Fatalf("append triage event failed: %v", err)
	}

	eventRows := sqlmock.NewRows([]string{"id", "finding_id", "action", "from_status", "to_status", "assignee", "suppression_expires_at", "comment", "actor", "created_at"}).
		AddRow("evt-2", "finding-1", FindingTriageActionCommented, "ack", "ack", "sec-oncall", nil, "reviewed", "subject:bob", now.Add(2*time.Minute)).
		AddRow("evt-1", "finding-1", FindingTriageActionAcknowledged, "open", "ack", "sec-oncall", expiry, "accepted risk", "subject:alice", now)
	mock.ExpectQuery("SELECT id, finding_id, action, from_status, to_status, assignee, suppression_expires_at, comment, actor, created_at").
		WithArgs("finding-1", "default", "default", 10).
		WillReturnRows(eventRows)

	events, err := store.ListFindingTriageEvents(defaultScopeContext(), "finding-1", 10)
	if err != nil {
		t.Fatalf("list triage events failed: %v", err)
	}
	if len(events) != 2 || events[0].ID != "evt-2" {
		t.Fatalf("unexpected triage events: %+v", events)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreApplyFindingTriageTransition(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO finding_triage_states").
		WithArgs("default", "default", "finding-1", "ack", "sec-oncall", nil, sqlmock.AnyArg(), "subject:alice").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO finding_triage_events").
		WithArgs(sqlmock.AnyArg(), "default", "default", "finding-1", FindingTriageActionAcknowledged, "open", "ack", "sec-oncall", nil, "acknowledged", "subject:alice", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = store.ApplyFindingTriageTransition(defaultScopeContext(), FindingTriageState{
		FindingID: "finding-1",
		Status:    domain.FindingLifecycleAck,
		Assignee:  "sec-oncall",
		UpdatedAt: now,
		UpdatedBy: "subject:alice",
	}, FindingTriageEvent{
		FindingID:  "finding-1",
		Action:     FindingTriageActionAcknowledged,
		FromStatus: domain.FindingLifecycleOpen,
		ToStatus:   domain.FindingLifecycleAck,
		Assignee:   "sec-oncall",
		Comment:    "acknowledged",
		Actor:      "subject:alice",
		CreatedAt:  now,
	})
	if err != nil {
		t.Fatalf("apply triage transition failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreApplyFindingTriageTransitionRollsBackOnEventFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO finding_triage_states").
		WithArgs("default", "default", "finding-1", "ack", "sec-oncall", nil, sqlmock.AnyArg(), "subject:alice").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO finding_triage_events").
		WithArgs(sqlmock.AnyArg(), "default", "default", "finding-1", FindingTriageActionAcknowledged, "open", "ack", "sec-oncall", nil, "acknowledged", "subject:alice", sqlmock.AnyArg()).
		WillReturnError(sql.ErrTxDone)
	mock.ExpectRollback()

	err = store.ApplyFindingTriageTransition(defaultScopeContext(), FindingTriageState{
		FindingID: "finding-1",
		Status:    domain.FindingLifecycleAck,
		Assignee:  "sec-oncall",
		UpdatedAt: now,
		UpdatedBy: "subject:alice",
	}, FindingTriageEvent{
		FindingID:  "finding-1",
		Action:     FindingTriageActionAcknowledged,
		FromStatus: domain.FindingLifecycleOpen,
		ToStatus:   domain.FindingLifecycleAck,
		Assignee:   "sec-oncall",
		Comment:    "acknowledged",
		Actor:      "subject:alice",
		CreatedAt:  now,
	})
	if err == nil {
		t.Fatal("expected triage transition error")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreScanQueueLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO scans (id, tenant_id, workspace_id, provider, status, started_at, asset_count, finding_count) VALUES ($1, $2, $3, $4, $5, $6, 0, 0)`)).
		WithArgs(sqlmock.AnyArg(), "default", "default", "aws", "queued", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	queued, err := store.CreateQueuedScan(defaultScopeContext(), "aws", now)
	if err != nil {
		t.Fatalf("create queued scan failed: %v", err)
	}
	if queued.Status != "queued" {
		t.Fatalf("expected queued status, got %q", queued.Status)
	}

	countRows := sqlmock.NewRows([]string{"count"}).AddRow(1)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)
		 FROM scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND provider = $3
		   AND status = 'queued'`)).
		WithArgs("default", "default", "aws").
		WillReturnRows(countRows)

	count, err := store.CountQueuedScans(defaultScopeContext(), "aws")
	if err != nil {
		t.Fatalf("count queued scans failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected queued count 1, got %d", count)
	}

	claimRows := sqlmock.NewRows([]string{"id", "tenant_id", "workspace_id", "provider", "status", "started_at", "finished_at", "asset_count", "finding_count", "coalesce"}).
		AddRow(queued.ID, "default", "default", "aws", "running", now, nil, 0, 0, "")
	mock.ExpectQuery("WITH next_scan AS").WithArgs("default", "default", "aws").WillReturnRows(claimRows)

	claimed, err := store.ClaimNextQueuedScan(defaultScopeContext(), "aws")
	if err != nil {
		t.Fatalf("claim queued scan failed: %v", err)
	}
	if claimed.Status != "running" {
		t.Fatalf("expected running status after claim, got %q", claimed.Status)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreRequiresScopeContext(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	if _, err := store.ListScans(context.Background(), 10); !errors.Is(err, ErrScopeRequired) {
		t.Fatalf("expected ErrScopeRequired, got %v", err)
	}
}

func TestPostgresStoreRepoQueueLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO repo_scans (id, tenant_id, workspace_id, repository, status, started_at, commits_scanned, files_scanned, finding_count, truncated, history_limit, max_findings_limit)
		 VALUES ($1, $2, $3, $4, $5, $6, 0, 0, 0, false, $7, $8)`)).
		WithArgs(sqlmock.AnyArg(), "default", "default", "owner/repo", "queued", sqlmock.AnyArg(), 50, 80).
		WillReturnResult(sqlmock.NewResult(1, 1))

	queued, err := store.CreateQueuedRepoScan(defaultScopeContext(), "owner/repo", 50, 80, now)
	if err != nil {
		t.Fatalf("create queued repo scan failed: %v", err)
	}
	if queued.Status != "queued" {
		t.Fatalf("expected queued status, got %q", queued.Status)
	}
	if queued.HistoryLimit != 50 || queued.MaxFindings != 80 {
		t.Fatalf("expected queued limits retained, got %+v", queued)
	}

	queuedCountRows := sqlmock.NewRows([]string{"count"}).AddRow(1)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)
		 FROM repo_scans
		 WHERE tenant_id = $1
		   AND workspace_id = $2
		   AND status = 'queued'`)).
		WithArgs("default", "default").
		WillReturnRows(queuedCountRows)

	queuedCount, err := store.CountQueuedRepoScans(defaultScopeContext())
	if err != nil {
		t.Fatalf("count queued repo scans failed: %v", err)
	}
	if queuedCount != 1 {
		t.Fatalf("expected queued count 1, got %d", queuedCount)
	}

	pendingRows := sqlmock.NewRows([]string{"count"}).AddRow(1)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*)
			 FROM repo_scans
			 WHERE tenant_id = $1
			   AND workspace_id = $2
			   AND LOWER(repository) = LOWER($3)
			   AND status IN ('queued', 'running')`)).
		WithArgs("default", "default", "OWNER/REPO").
		WillReturnRows(pendingRows)

	pendingCount, err := store.CountPendingRepoScansByRepository(defaultScopeContext(), "OWNER/REPO")
	if err != nil {
		t.Fatalf("count pending repo scans failed: %v", err)
	}
	if pendingCount != 1 {
		t.Fatalf("expected pending count 1, got %d", pendingCount)
	}

	claimRows := sqlmock.NewRows([]string{
		"id",
		"tenant_id",
		"workspace_id",
		"repository",
		"status",
		"started_at",
		"finished_at",
		"commits_scanned",
		"files_scanned",
		"finding_count",
		"truncated",
		"coalesce",
		"history_limit",
		"max_findings_limit",
	}).AddRow(queued.ID, "default", "default", "owner/repo", "running", now, nil, 0, 0, 0, false, "", 50, 80)
	mock.ExpectQuery("WITH next_repo_scan AS").WithArgs("default", "default").WillReturnRows(claimRows)

	claimed, err := store.ClaimNextQueuedRepoScan(defaultScopeContext())
	if err != nil {
		t.Fatalf("claim queued repo scan failed: %v", err)
	}
	if claimed.Status != "running" {
		t.Fatalf("expected running status, got %q", claimed.Status)
	}

	mock.ExpectExec(regexp.QuoteMeta(`UPDATE repo_scans
		 SET status = 'queued',
		     started_at = NOW(),
		     finished_at = NULL,
		     error_message = NULL
		 WHERE id = $1
		   AND tenant_id = $2
		   AND workspace_id = $3
		   AND status = 'running'`)).
		WithArgs(claimed.ID, "default", "default").
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := store.RequeueRepoScan(defaultScopeContext(), claimed.ID); err != nil {
		t.Fatalf("requeue repo scan failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreAuthzEntityAttributesLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	mock.ExpectExec("INSERT INTO authz_entity_attributes").
		WithArgs(
			"default",
			"default",
			AuthzEntityKindResource,
			"finding",
			"finding-1",
			"platform_sec",
			AuthzAttributeEnvProd,
			AuthzAttributeRiskTierHigh,
			AuthzAttributeClassificationConfidential,
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.UpsertAuthzEntityAttributes(defaultScopeContext(), AuthzEntityAttributes{
		EntityKind:     AuthzEntityKindResource,
		EntityType:     "finding",
		EntityID:       "finding-1",
		OwnerTeam:      "platform_sec",
		Environment:    AuthzAttributeEnvProd,
		RiskTier:       AuthzAttributeRiskTierHigh,
		Classification: AuthzAttributeClassificationConfidential,
	}); err != nil {
		t.Fatalf("upsert authz attributes: %v", err)
	}

	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"tenant_id",
		"workspace_id",
		"entity_kind",
		"entity_type",
		"entity_id",
		"owner_team",
		"env",
		"risk_tier",
		"classification",
		"updated_at",
	}).AddRow("default", "default", AuthzEntityKindResource, "finding", "finding-1", "platform_sec", AuthzAttributeEnvProd, AuthzAttributeRiskTierHigh, AuthzAttributeClassificationConfidential, now)
	mock.ExpectQuery("SELECT tenant_id, workspace_id, entity_kind, entity_type, entity_id").
		WithArgs("default", "default", AuthzEntityKindResource, "finding", "finding-1").
		WillReturnRows(rows)

	record, err := store.GetAuthzEntityAttributes(defaultScopeContext(), AuthzEntityKindResource, "finding", "finding-1")
	if err != nil {
		t.Fatalf("get authz attributes: %v", err)
	}
	if record.OwnerTeam != "platform_sec" || record.Environment != AuthzAttributeEnvProd {
		t.Fatalf("unexpected authz attributes %+v", record)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreAuthzRelationshipLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	mock.ExpectExec("INSERT INTO authz_relationships").
		WithArgs(
			"default",
			"default",
			"user",
			"alice",
			AuthzRelationshipManages,
			"workspace",
			"workspace-1",
			"sync",
			nil,
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.UpsertAuthzRelationship(defaultScopeContext(), AuthzRelationship{
		SubjectType: "user",
		SubjectID:   "alice",
		Relation:    AuthzRelationshipManages,
		ObjectType:  "workspace",
		ObjectID:    "workspace-1",
		Source:      "sync",
	}); err != nil {
		t.Fatalf("upsert authz relationship: %v", err)
	}

	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"tenant_id",
		"workspace_id",
		"subject_type",
		"subject_id",
		"relation",
		"object_type",
		"object_id",
		"source",
		"expires_at",
		"created_at",
		"updated_at",
	}).AddRow("default", "default", "user", "alice", AuthzRelationshipManages, "workspace", "workspace-1", "sync", nil, now, now)
	mock.ExpectQuery("SELECT tenant_id, workspace_id, subject_type, subject_id, relation, object_type, object_id, source, expires_at, created_at, updated_at").
		WithArgs("default", "default", "user", "alice", sqlmock.AnyArg(), 10).
		WillReturnRows(rows)

	relationships, err := store.ListAuthzRelationships(defaultScopeContext(), AuthzRelationshipFilter{
		SubjectType: "user",
		SubjectID:   "alice",
	}, 10)
	if err != nil {
		t.Fatalf("list authz relationships: %v", err)
	}
	if len(relationships) != 1 || relationships[0].Relation != AuthzRelationshipManages {
		t.Fatalf("unexpected authz relationships: %+v", relationships)
	}

	mock.ExpectExec("DELETE FROM authz_relationships").
		WithArgs("default", "default", "user", "alice", AuthzRelationshipManages, "workspace", "workspace-1").
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := store.DeleteAuthzRelationship(defaultScopeContext(), AuthzRelationship{
		SubjectType: "user",
		SubjectID:   "alice",
		Relation:    AuthzRelationshipManages,
		ObjectType:  "workspace",
		ObjectID:    "workspace-1",
	}); err != nil {
		t.Fatalf("delete authz relationship: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreListAuthzRelationshipsWithFullFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"tenant_id",
		"workspace_id",
		"subject_type",
		"subject_id",
		"relation",
		"object_type",
		"object_id",
		"source",
		"expires_at",
		"created_at",
		"updated_at",
	}).AddRow("default", "default", "user", "alice", AuthzRelationshipManages, "workspace", "workspace-1", "manual", now, now, now)
	mock.ExpectQuery("SELECT tenant_id, workspace_id, subject_type, subject_id, relation, object_type, object_id, source, expires_at, created_at, updated_at").
		WithArgs("default", "default", "user", "alice", AuthzRelationshipManages, "workspace", "workspace-1").
		WillReturnRows(rows)

	relationships, err := store.ListAuthzRelationships(defaultScopeContext(), AuthzRelationshipFilter{
		SubjectType:    "user",
		SubjectID:      "alice",
		Relation:       AuthzRelationshipManages,
		ObjectType:     "workspace",
		ObjectID:       "workspace-1",
		IncludeExpired: true,
	}, 0)
	if err != nil {
		t.Fatalf("list authz relationships with full filters: %v", err)
	}
	if len(relationships) != 1 {
		t.Fatalf("expected one relationship, got %d", len(relationships))
	}
	if relationships[0].ExpiresAt == nil {
		t.Fatalf("expected expires_at to be populated")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreListAuthzRelationshipsRejectsInvalidRelationFilter(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	if _, err := store.ListAuthzRelationships(defaultScopeContext(), AuthzRelationshipFilter{
		Relation: "viewer",
	}, 10); err == nil {
		t.Fatal("expected invalid relation filter error")
	}
}

func TestPostgresStoreAuthzPolicySetLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	mock.ExpectExec("INSERT INTO authz_policy_sets").
		WithArgs(
			"default",
			"default",
			"core_policy",
			"Core Policy",
			"workspace baseline",
			"owner",
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.UpsertAuthzPolicySet(defaultScopeContext(), AuthzPolicySet{
		PolicySetID: "core_policy",
		DisplayName: "Core Policy",
		Description: "workspace baseline",
		CreatedBy:   "owner",
	}); err != nil {
		t.Fatalf("upsert authz policy set: %v", err)
	}

	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"tenant_id",
		"workspace_id",
		"policy_set_id",
		"display_name",
		"description",
		"created_by",
		"created_at",
		"updated_at",
	}).AddRow("default", "default", "core_policy", "Core Policy", "workspace baseline", "owner", now, now)
	mock.ExpectQuery("SELECT tenant_id, workspace_id, policy_set_id, display_name").
		WithArgs("default", "default", "core_policy").
		WillReturnRows(rows)

	record, err := store.GetAuthzPolicySet(defaultScopeContext(), "core_policy")
	if err != nil {
		t.Fatalf("get authz policy set: %v", err)
	}
	if record.DisplayName != "Core Policy" || record.PolicySetID != "core_policy" {
		t.Fatalf("unexpected authz policy set %+v", record)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreAuthzPolicyVersionLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	setRows := sqlmock.NewRows([]string{
		"tenant_id",
		"workspace_id",
		"policy_set_id",
		"display_name",
		"description",
		"created_by",
		"created_at",
		"updated_at",
	}).AddRow("default", "default", "core_policy", "Core Policy", "workspace baseline", "owner", now, now)
	mock.ExpectQuery("SELECT tenant_id, workspace_id, policy_set_id, display_name").
		WithArgs("default", "default", "core_policy").
		WillReturnRows(setRows)

	createdRows := sqlmock.NewRows([]string{
		"tenant_id",
		"workspace_id",
		"policy_set_id",
		"version",
		"bundle",
		"checksum",
		"created_by",
		"created_at",
	}).AddRow(
		"default",
		"default",
		"core_policy",
		1,
		`{"rules":[{"id":"allow-read","effect":"allow"}]}`,
		"7d506f99ea690c4297132763253db76fb6cc4eed6a7307b3dbd83eb9b1618240",
		"owner",
		now,
	)
	mock.ExpectQuery("INSERT INTO authz_policy_versions").
		WithArgs(
			"default",
			"default",
			"core_policy",
			1,
			`{"rules":[{"id":"allow-read","effect":"allow"}]}`,
			"7d506f99ea690c4297132763253db76fb6cc4eed6a7307b3dbd83eb9b1618240",
			"owner",
			sqlmock.AnyArg(),
		).
		WillReturnRows(createdRows)

	created, err := store.CreateAuthzPolicyVersion(defaultScopeContext(), AuthzPolicyVersion{
		PolicySetID: "core_policy",
		Version:     1,
		Bundle:      `{"rules":[{"id":"allow-read","effect":"allow"}]}`,
		CreatedBy:   "owner",
	})
	if err != nil {
		t.Fatalf("create authz policy version: %v", err)
	}
	if created.Version != 1 || created.PolicySetID != "core_policy" {
		t.Fatalf("unexpected created version %+v", created)
	}

	getRows := sqlmock.NewRows([]string{
		"tenant_id",
		"workspace_id",
		"policy_set_id",
		"version",
		"bundle",
		"checksum",
		"created_by",
		"created_at",
	}).AddRow(
		"default",
		"default",
		"core_policy",
		1,
		`{"rules":[{"id":"allow-read","effect":"allow"}]}`,
		created.Checksum,
		"owner",
		now,
	)
	mock.ExpectQuery("SELECT tenant_id, workspace_id, policy_set_id, version, bundle::text, checksum").
		WithArgs("default", "default", "core_policy", 1).
		WillReturnRows(getRows)

	got, err := store.GetAuthzPolicyVersion(defaultScopeContext(), "core_policy", 1)
	if err != nil {
		t.Fatalf("get authz policy version: %v", err)
	}
	if got.Checksum != created.Checksum {
		t.Fatalf("unexpected checksum from get: %s", got.Checksum)
	}

	listRows := sqlmock.NewRows([]string{
		"tenant_id",
		"workspace_id",
		"policy_set_id",
		"version",
		"bundle",
		"checksum",
		"created_by",
		"created_at",
	}).AddRow(
		"default",
		"default",
		"core_policy",
		1,
		`{"rules":[{"id":"allow-read","effect":"allow"}]}`,
		created.Checksum,
		"owner",
		now,
	)
	mock.ExpectQuery("SELECT tenant_id, workspace_id, policy_set_id, version, bundle::text, checksum").
		WithArgs("default", "default", "core_policy", 10).
		WillReturnRows(listRows)

	versions, err := store.ListAuthzPolicyVersions(defaultScopeContext(), "core_policy", 10)
	if err != nil {
		t.Fatalf("list authz policy versions: %v", err)
	}
	if len(versions) != 1 || versions[0].Version != 1 {
		t.Fatalf("unexpected listed versions %+v", versions)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreCreateAuthzPolicyVersionAutoIncrementWithRetry(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	now := time.Now().UTC()

	setRows := sqlmock.NewRows([]string{
		"tenant_id",
		"workspace_id",
		"policy_set_id",
		"display_name",
		"description",
		"created_by",
		"created_at",
		"updated_at",
	}).AddRow("default", "default", "core_policy", "Core Policy", "workspace baseline", "owner", now, now)
	mock.ExpectQuery("SELECT tenant_id, workspace_id, policy_set_id, display_name").
		WithArgs("default", "default", "core_policy").
		WillReturnRows(setRows)

	// First attempt returns no rows (simulates an ON CONFLICT DO NOTHING race).
	mock.ExpectQuery("INSERT INTO authz_policy_versions").
		WithArgs(
			"default",
			"default",
			"core_policy",
			`{"rules":[{"id":"allow-write","effect":"allow"}]}`,
			"a07bdecc388142a8c92166c6c3dc619deadedefb01305d6d528db73245eee201",
			"owner",
			sqlmock.AnyArg(),
		).
		WillReturnRows(sqlmock.NewRows([]string{
			"tenant_id",
			"workspace_id",
			"policy_set_id",
			"version",
			"bundle",
			"checksum",
			"created_by",
			"created_at",
		}))

	createdRows := sqlmock.NewRows([]string{
		"tenant_id",
		"workspace_id",
		"policy_set_id",
		"version",
		"bundle",
		"checksum",
		"created_by",
		"created_at",
	}).AddRow(
		"default",
		"default",
		"core_policy",
		3,
		`{"rules":[{"id":"allow-write","effect":"allow"}]}`,
		"a07bdecc388142a8c92166c6c3dc619deadedefb01305d6d528db73245eee201",
		"owner",
		now,
	)
	mock.ExpectQuery("INSERT INTO authz_policy_versions").
		WithArgs(
			"default",
			"default",
			"core_policy",
			`{"rules":[{"id":"allow-write","effect":"allow"}]}`,
			"a07bdecc388142a8c92166c6c3dc619deadedefb01305d6d528db73245eee201",
			"owner",
			sqlmock.AnyArg(),
		).
		WillReturnRows(createdRows)

	created, err := store.CreateAuthzPolicyVersion(defaultScopeContext(), AuthzPolicyVersion{
		PolicySetID: "core_policy",
		Bundle:      `{"rules":[{"id":"allow-write","effect":"allow"}]}`,
		CreatedBy:   "owner",
	})
	if err != nil {
		t.Fatalf("create authz policy version with auto-increment: %v", err)
	}
	if created.Version != 3 {
		t.Fatalf("expected auto-incremented version 3, got %d", created.Version)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreAuthzPolicyRolloutLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	active := 1
	candidate := 2
	mock.ExpectExec("INSERT INTO authz_policy_rollouts").
		WithArgs(
			"default",
			"default",
			"core_policy",
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			AuthzPolicyRolloutModeShadow,
			"owner",
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.UpsertAuthzPolicyRollout(defaultScopeContext(), AuthzPolicyRollout{
		PolicySetID:      "core_policy",
		ActiveVersion:    &active,
		CandidateVersion: &candidate,
		Mode:             AuthzPolicyRolloutModeShadow,
		UpdatedBy:        "owner",
	}); err != nil {
		t.Fatalf("upsert authz policy rollout: %v", err)
	}

	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"tenant_id",
		"workspace_id",
		"policy_set_id",
		"active_version",
		"candidate_version",
		"mode",
		"updated_by",
		"updated_at",
	}).AddRow("default", "default", "core_policy", int64(1), int64(2), AuthzPolicyRolloutModeShadow, "owner", now)
	mock.ExpectQuery("SELECT tenant_id, workspace_id, policy_set_id, active_version, candidate_version, mode, COALESCE\\(updated_by, ''\\), updated_at").
		WithArgs("default", "default", "core_policy").
		WillReturnRows(rows)

	rollout, err := store.GetAuthzPolicyRollout(defaultScopeContext(), "core_policy")
	if err != nil {
		t.Fatalf("get authz policy rollout: %v", err)
	}
	if rollout.ActiveVersion == nil || rollout.CandidateVersion == nil {
		t.Fatalf("expected rollout versions to be present: %+v", rollout)
	}
	if *rollout.ActiveVersion != 1 || *rollout.CandidateVersion != 2 {
		t.Fatalf("unexpected rollout versions: %+v", rollout)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreAuthzPolicyEventsLifecycle(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	fromVersion := 1
	toVersion := 2
	mock.ExpectExec("INSERT INTO authz_policy_events").
		WithArgs(
			sqlmock.AnyArg(),
			"default",
			"default",
			"core_policy",
			"promote",
			&fromVersion,
			&toVersion,
			"owner",
			"promoted candidate",
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	if err := store.AppendAuthzPolicyEvent(defaultScopeContext(), AuthzPolicyEvent{
		PolicySetID: "core_policy",
		EventType:   "promote",
		FromVersion: &fromVersion,
		ToVersion:   &toVersion,
		Actor:       "owner",
		Message:     "promoted candidate",
		Metadata:    map[string]any{"source": "test"},
	}); err != nil {
		t.Fatalf("append authz policy event: %v", err)
	}

	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"id",
		"tenant_id",
		"workspace_id",
		"policy_set_id",
		"event_type",
		"from_version",
		"to_version",
		"actor",
		"message",
		"metadata",
		"created_at",
	}).AddRow(
		"event-1",
		"default",
		"default",
		"core_policy",
		"promote",
		int64(1),
		int64(2),
		"owner",
		"promoted candidate",
		[]byte(`{"source":"test"}`),
		now,
	)
	mock.ExpectQuery("SELECT id, tenant_id, workspace_id, policy_set_id, event_type, from_version, to_version").
		WithArgs("default", "default", "core_policy", 10).
		WillReturnRows(rows)

	events, err := store.ListAuthzPolicyEvents(defaultScopeContext(), "core_policy", 10)
	if err != nil {
		t.Fatalf("list authz policy events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Metadata["source"] != "test" {
		t.Fatalf("unexpected event metadata: %+v", events[0].Metadata)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreInjectScopeCTEBypassWhenDisabled(t *testing.T) {
	store := &PostgresStore{}
	query := "SELECT id FROM scans WHERE tenant_id = $1"
	args := []any{"tenant-a"}

	gotQuery, gotArgs, err := store.injectScopeCTE(defaultScopeContext(), query, args)
	if err != nil {
		t.Fatalf("inject scope cte: %v", err)
	}
	if gotQuery != query {
		t.Fatalf("expected query unchanged, got %q", gotQuery)
	}
	if !reflect.DeepEqual(gotArgs, args) {
		t.Fatalf("expected args unchanged, got %+v", gotArgs)
	}
}

func TestPostgresStoreInjectScopeCTERewritesQueryWhenEnabled(t *testing.T) {
	store := &PostgresStore{}
	store.SetScopeRLSEnforcement(true)

	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	query := "SELECT id FROM scans WHERE tenant_id = $1 AND workspace_id = $2 LIMIT $3"
	args := []any{"tenant-a", "workspace-a", 10}

	gotQuery, gotArgs, err := store.injectScopeCTE(ctx, query, args)
	if err != nil {
		t.Fatalf("inject scope cte: %v", err)
	}

	expectedQuery := "WITH _identrail_scope AS (SELECT set_config('identrail.tenant_id', $4, true), set_config('identrail.workspace_id', $5, true), set_config('identrail.rls_enforce', $6, true)) " + query
	if gotQuery != expectedQuery {
		t.Fatalf("unexpected rewritten query:\nexpected: %s\ngot:      %s", expectedQuery, gotQuery)
	}

	expectedArgs := []any{"tenant-a", "workspace-a", 10, "tenant-a", "workspace-a", "on"}
	if !reflect.DeepEqual(gotArgs, expectedArgs) {
		t.Fatalf("unexpected rewritten args: %+v", gotArgs)
	}
}

func TestPostgresStoreInjectScopeCTEHandlesWithRecursive(t *testing.T) {
	store := &PostgresStore{}
	store.SetScopeRLSEnforcement(true)

	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	query := "WITH RECURSIVE chain AS (SELECT 1 AS n) SELECT n FROM chain"

	gotQuery, gotArgs, err := store.injectScopeCTE(ctx, query, nil)
	if err != nil {
		t.Fatalf("inject scope cte: %v", err)
	}

	expectedQuery := "WITH RECURSIVE _identrail_scope AS (SELECT set_config('identrail.tenant_id', $1, true), set_config('identrail.workspace_id', $2, true), set_config('identrail.rls_enforce', $3, true)), chain AS (SELECT 1 AS n) SELECT n FROM chain"
	if gotQuery != expectedQuery {
		t.Fatalf("unexpected recursive rewritten query:\nexpected: %s\ngot:      %s", expectedQuery, gotQuery)
	}

	expectedArgs := []any{"tenant-a", "workspace-a", "on"}
	if !reflect.DeepEqual(gotArgs, expectedArgs) {
		t.Fatalf("unexpected rewritten args: %+v", gotArgs)
	}
}

func TestPostgresStoreInjectScopeCTERequiresScopeWhenEnabled(t *testing.T) {
	store := &PostgresStore{}
	store.SetScopeRLSEnforcement(true)

	if _, _, err := store.injectScopeCTE(context.Background(), "SELECT 1", nil); !errors.Is(err, ErrScopeRequired) {
		t.Fatalf("expected ErrScopeRequired, got %v", err)
	}
}

func TestPostgresStoreBeginTxSetsRLSScopeContext(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	store.SetScopeRLSEnforcement(true)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`SELECT set_config('identrail.tenant_id', $1, true), set_config('identrail.workspace_id', $2, true), set_config('identrail.rls_enforce', $3, true)`)).
		WithArgs("default", "default", "on").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectRollback()

	tx, err := store.beginTx(defaultScopeContext())
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback tx: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresStoreBeginTxRequiresScopeWhenRLSEnabled(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	store.SetScopeRLSEnforcement(true)

	mock.ExpectBegin()
	mock.ExpectRollback()

	if _, err := store.beginTx(context.Background()); !errors.Is(err, ErrScopeRequired) {
		t.Fatalf("expected ErrScopeRequired, got %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestCheckedSliceCapacity(t *testing.T) {
	got, err := checkedSliceCapacity(4, 3)
	if err != nil {
		t.Fatalf("checked slice capacity: %v", err)
	}
	if got != 7 {
		t.Fatalf("expected capacity 7, got %d", got)
	}

	maxInt := int(^uint(0) >> 1)
	if _, err := checkedSliceCapacity(maxInt, 1); !errors.Is(err, errQueryArgCapacityOverflow) {
		t.Fatalf("expected overflow error, got %v", err)
	}

	if _, err := checkedSliceCapacity(-1, 1); err == nil {
		t.Fatal("expected invalid input error")
	}
}

func TestPostgresStoreDBAndScopeFlagHelpers(t *testing.T) {
	var nilStore *PostgresStore
	if got := nilStore.DB(); got != nil {
		t.Fatalf("expected nil DB from nil store, got %v", got)
	}
	if nilStore.ScopeRLSEnforcementEnabled() {
		t.Fatal("expected nil store scope rls enforcement to be false")
	}

	sqlDB := &sql.DB{}
	store := NewPostgresStoreWithDB(sqlDB)
	if got := store.DB(); got != sqlDB {
		t.Fatalf("expected DB pointer to match")
	}
	if store.ScopeRLSEnforcementEnabled() {
		t.Fatal("expected scope rls enforcement disabled by default")
	}

	store.SetScopeRLSEnforcement(true)
	if !store.ScopeRLSEnforcementEnabled() {
		t.Fatal("expected scope rls enforcement enabled")
	}
}

func TestPostgresStoreWrapperScopeErrors(t *testing.T) {
	store := &PostgresStore{}
	store.SetScopeRLSEnforcement(true)

	if _, err := store.execContext(context.Background(), "SELECT 1"); !errors.Is(err, ErrScopeRequired) {
		t.Fatalf("expected ErrScopeRequired from execContext, got %v", err)
	}
	if _, err := store.queryContext(context.Background(), "SELECT 1"); !errors.Is(err, ErrScopeRequired) {
		t.Fatalf("expected ErrScopeRequired from queryContext, got %v", err)
	}
	if err := store.queryRowContext(context.Background(), "SELECT 1").Scan(new(int)); !errors.Is(err, ErrScopeRequired) {
		t.Fatalf("expected ErrScopeRequired from queryRowContext scan, got %v", err)
	}
}

func TestErrorsIsNoRows(t *testing.T) {
	if !errorsIsNoRows(sql.ErrNoRows) {
		t.Fatal("expected true for sql.ErrNoRows")
	}
	if errorsIsNoRows(errors.New("different error")) {
		t.Fatal("expected false for non-no-rows error")
	}
}
