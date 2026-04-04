package db

import (
	"context"
	"database/sql"
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

	scan, err := store.CreateScan(context.Background(), "aws", time.Now())
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

	if err := store.CompleteScan(context.Background(), scan.ID, "completed", time.Now(), 2, 1, ""); err != nil {
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

	if err := store.UpsertFindings(context.Background(), "scan-1", findings); err != nil {
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

	err = store.UpsertArtifacts(context.Background(), "scan-1", ScanArtifacts{
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

	scans, err := store.ListScans(context.Background(), 20)
	if err != nil {
		t.Fatalf("list scans failed: %v", err)
	}
	if len(scans) != 1 || scans[0].ID != "scan-1" {
		t.Fatalf("unexpected scans: %+v", scans)
	}

	findingsRows := sqlmock.NewRows([]string{"scan_id", "finding_id", "type", "severity", "title", "human_summary", "path", "evidence", "remediation", "created_at"}).
		AddRow("scan-1", "f1", "ownerless_identity", "medium", "Ownerless", "summary", []byte("[\"x\"]"), []byte("{\"a\":1}"), "fix", now)
	mock.ExpectQuery("SELECT f.scan_id, f.finding_id, f.type").WithArgs("default", "default", 100).WillReturnRows(findingsRows)

	findings, err := store.ListFindings(context.Background(), 100)
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

	scan, err := store.GetScan(context.Background(), "scan-1")
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

	findings, err := store.ListFindingsByScan(context.Background(), "scan-1", 100)
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

	if err := store.AppendScanEvent(context.Background(), "scan-1", "info", "scan started", map[string]any{"provider": "aws"}); err != nil {
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

	events, err := store.ListScanEvents(context.Background(), "scan-1", 10)
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
	if err := store.AppendScanEvent(context.Background(), "scan-1", "invalid", "bad", nil); err == nil {
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

	identities, err := store.ListIdentities(context.Background(), IdentityFilter{
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

	relationships, err := store.ListRelationships(context.Background(), RelationshipFilter{Type: "can_assume"}, 30)
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

	record, err := store.CreateRepoScan(context.Background(), "owner/repo", now)
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

	if err := store.UpsertRepoFindings(context.Background(), record.ID, []domain.Finding{{
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

	if err := store.CompleteRepoScan(context.Background(), record.ID, "completed", now, 12, 8, 1, false, ""); err != nil {
		t.Fatalf("complete repo scan failed: %v", err)
	}

	repoScanRows := sqlmock.NewRows([]string{"id", "tenant_id", "workspace_id", "repository", "status", "started_at", "finished_at", "commits_scanned", "files_scanned", "finding_count", "truncated", "error_message", "history_limit", "max_findings_limit"}).
		AddRow(record.ID, "default", "default", "owner/repo", "completed", now, now, 12, 8, 1, false, "", 0, 0)
	mock.ExpectQuery("SELECT id, tenant_id, workspace_id, repository, status").WithArgs("default", "default", 20).WillReturnRows(repoScanRows)
	repoScans, err := store.ListRepoScans(context.Background(), 20)
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
	repoFindings, err := store.ListRepoFindings(context.Background(), RepoFindingFilter{RepoScanID: record.ID}, 100)
	if err != nil {
		t.Fatalf("list repo findings failed: %v", err)
	}
	if len(repoFindings) != 1 || repoFindings[0].ID != "rf-1" {
		t.Fatalf("unexpected repo findings: %+v", repoFindings)
	}

	repoScanRow := sqlmock.NewRows([]string{"id", "tenant_id", "workspace_id", "repository", "status", "started_at", "finished_at", "commits_scanned", "files_scanned", "finding_count", "truncated", "error_message", "history_limit", "max_findings_limit"}).
		AddRow(record.ID, "default", "default", "owner/repo", "completed", now, now, 12, 8, 1, false, "", 0, 0)
	mock.ExpectQuery("SELECT id, tenant_id, workspace_id, repository, status").WithArgs(record.ID, "default", "default").WillReturnRows(repoScanRow)
	gotRepoScan, err := store.GetRepoScan(context.Background(), record.ID)
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

	queued, err := store.CreateQueuedScan(context.Background(), "aws", now)
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

	count, err := store.CountQueuedScans(context.Background(), "aws")
	if err != nil {
		t.Fatalf("count queued scans failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected queued count 1, got %d", count)
	}

	claimRows := sqlmock.NewRows([]string{"id", "tenant_id", "workspace_id", "provider", "status", "started_at", "finished_at", "asset_count", "finding_count", "coalesce"}).
		AddRow(queued.ID, "default", "default", "aws", "running", now, nil, 0, 0, "")
	mock.ExpectQuery("WITH next_scan AS").WithArgs("default", "default", "aws").WillReturnRows(claimRows)

	claimed, err := store.ClaimNextQueuedScan(context.Background(), "aws")
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

	queued, err := store.CreateQueuedRepoScan(context.Background(), "owner/repo", 50, 80, now)
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

	queuedCount, err := store.CountQueuedRepoScans(context.Background())
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

	pendingCount, err := store.CountPendingRepoScansByRepository(context.Background(), "OWNER/REPO")
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

	claimed, err := store.ClaimNextQueuedRepoScan(context.Background())
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

	if err := store.RequeueRepoScan(context.Background(), claimed.ID); err != nil {
		t.Fatalf("requeue repo scan failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
