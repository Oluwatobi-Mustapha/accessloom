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

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO scans (id, provider, status, started_at, asset_count, finding_count) VALUES ($1, $2, $3, $4, 0, 0)`)).
		WithArgs(sqlmock.AnyArg(), "aws", "running", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	scan, err := store.CreateScan(context.Background(), "aws", time.Now())
	if err != nil {
		t.Fatalf("create scan failed: %v", err)
	}

	mock.ExpectExec(regexp.QuoteMeta(`UPDATE scans SET status=$2, finished_at=$3, asset_count=$4, finding_count=$5, error_message=$6 WHERE id=$1`)).
		WithArgs(scan.ID, "completed", sqlmock.AnyArg(), 2, 1, nil).
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

	scanRows := sqlmock.NewRows([]string{"id", "provider", "status", "started_at", "finished_at", "asset_count", "finding_count", "error_message"}).
		AddRow("scan-1", "aws", "completed", now, now, 2, 1, "")
	mock.ExpectQuery("SELECT id, provider, status").WithArgs(20).WillReturnRows(scanRows)

	scans, err := store.ListScans(context.Background(), 20)
	if err != nil {
		t.Fatalf("list scans failed: %v", err)
	}
	if len(scans) != 1 || scans[0].ID != "scan-1" {
		t.Fatalf("unexpected scans: %+v", scans)
	}

	findingsRows := sqlmock.NewRows([]string{"scan_id", "finding_id", "type", "severity", "title", "human_summary", "path", "evidence", "remediation", "created_at"}).
		AddRow("scan-1", "f1", "ownerless_identity", "medium", "Ownerless", "summary", []byte("[\"x\"]"), []byte("{\"a\":1}"), "fix", now)
	mock.ExpectQuery("SELECT scan_id, finding_id, type").WithArgs(100).WillReturnRows(findingsRows)

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

func TestNewPostgresStoreWithDB(t *testing.T) {
	store := NewPostgresStoreWithDB(&sql.DB{})
	if store == nil {
		t.Fatal("expected store")
	}
}
