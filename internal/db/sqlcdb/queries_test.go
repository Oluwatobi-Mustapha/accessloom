package sqlcdb

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestQueriesGetScan(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	q := New(db)
	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{"id", "provider", "status", "started_at", "finished_at", "asset_count", "finding_count", "coalesce"}).
		AddRow("scan-1", "aws", "completed", now, now, 2, 1, "")
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, provider, status, started_at, finished_at, asset_count, finding_count, COALESCE(error_message, '')
		 FROM scans
		 WHERE id = $1`)).WithArgs("scan-1").WillReturnRows(rows)

	scan, err := q.GetScan(context.Background(), "scan-1")
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if scan.ID != "scan-1" {
		t.Fatalf("unexpected scan id %q", scan.ID)
	}
}

func TestQueriesListFindingsByScan(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	q := New(db)
	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{"scan_id", "finding_id", "type", "severity", "title", "human_summary", "path", "evidence", "remediation", "created_at"}).
		AddRow("scan-1", "f1", "ownerless_identity", "high", "Ownerless", "summary", []byte("[]"), []byte("{}"), "fix", now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT scan_id, finding_id, type, severity, title, human_summary, path, evidence, remediation, created_at
		 FROM findings
		 WHERE scan_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2`)).WithArgs("scan-1", 100).WillReturnRows(rows)

	result, err := q.ListFindingsByScan(context.Background(), "scan-1", 100)
	if err != nil {
		t.Fatalf("list findings by scan: %v", err)
	}
	if len(result) != 1 || result[0].FindingID != "f1" {
		t.Fatalf("unexpected results: %+v", result)
	}
}

func TestQueriesListRepoScans(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	q := New(db)
	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{"id", "repository", "status", "started_at", "finished_at", "commits_scanned", "files_scanned", "finding_count", "truncated", "coalesce"}).
		AddRow("repo-scan-1", "owner/repo", "completed", now, now, 10, 5, 2, false, "")
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, repository, status, started_at, finished_at, commits_scanned, files_scanned, finding_count, truncated, COALESCE(error_message, '')
		 FROM repo_scans
		 ORDER BY started_at DESC
		 LIMIT $1`)).WithArgs(20).WillReturnRows(rows)

	result, err := q.ListRepoScans(context.Background(), 20)
	if err != nil {
		t.Fatalf("list repo scans: %v", err)
	}
	if len(result) != 1 || result[0].ID != "repo-scan-1" {
		t.Fatalf("unexpected results: %+v", result)
	}
}

func TestQueriesListScans(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	q := New(db)
	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{"id", "provider", "status", "started_at", "finished_at", "asset_count", "finding_count", "coalesce"}).
		AddRow("scan-1", "aws", "completed", now, now, 3, 1, "")
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, provider, status, started_at, finished_at, asset_count, finding_count, COALESCE(error_message, '')
		 FROM scans
		 ORDER BY started_at DESC
		 LIMIT $1`)).WithArgs(20).WillReturnRows(rows)

	result, err := q.ListScans(context.Background(), 20)
	if err != nil {
		t.Fatalf("list scans: %v", err)
	}
	if len(result) != 1 || result[0].ID != "scan-1" {
		t.Fatalf("unexpected scans: %+v", result)
	}
}

func TestQueriesListScanEvents(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	q := New(db)
	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{"id", "scan_id", "level", "message", "metadata", "created_at"}).
		AddRow("ev-1", "scan-1", "info", "started", []byte(`{"k":"v"}`), now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, scan_id, level, message, metadata, created_at
		 FROM scan_events
		 WHERE scan_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2`)).WithArgs("scan-1", 50).WillReturnRows(rows)

	result, err := q.ListScanEvents(context.Background(), "scan-1", 50)
	if err != nil {
		t.Fatalf("list scan events: %v", err)
	}
	if len(result) != 1 || result[0].ID != "ev-1" {
		t.Fatalf("unexpected events: %+v", result)
	}
}

func TestQueriesGetRepoScan(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	q := New(db)
	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{"id", "repository", "status", "started_at", "finished_at", "commits_scanned", "files_scanned", "finding_count", "truncated", "coalesce"}).
		AddRow("repo-scan-1", "owner/repo", "completed", now, now, 20, 10, 2, false, "")
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, repository, status, started_at, finished_at, commits_scanned, files_scanned, finding_count, truncated, COALESCE(error_message, '')
		 FROM repo_scans
		 WHERE id = $1`)).WithArgs("repo-scan-1").WillReturnRows(rows)

	result, err := q.GetRepoScan(context.Background(), "repo-scan-1")
	if err != nil {
		t.Fatalf("get repo scan: %v", err)
	}
	if result.ID != "repo-scan-1" {
		t.Fatalf("unexpected repo scan: %+v", result)
	}
}

func TestQueriesListRepoFindings(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	q := New(db)
	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{"repo_scan_id", "finding_id", "type", "severity", "title", "human_summary", "path", "evidence", "remediation", "created_at"}).
		AddRow("repo-scan-1", "rf-1", "secret_exposure", "high", "secret", "summary", []byte(`["a"]`), []byte(`{"k":"v"}`), "fix", now)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT repo_scan_id, finding_id, type, severity, title, human_summary, path, evidence, remediation, created_at
		 FROM repo_findings
		 WHERE ($1 = '' OR repo_scan_id = $1::uuid)
		   AND ($2 = '' OR severity = $2)
		   AND ($3 = '' OR type = $3)
		 ORDER BY created_at DESC
		 LIMIT $4`)).
		WithArgs("repo-scan-1", "high", "secret_exposure", 25).
		WillReturnRows(rows)

	result, err := q.ListRepoFindings(context.Background(), "repo-scan-1", "high", "secret_exposure", 25)
	if err != nil {
		t.Fatalf("list repo findings: %v", err)
	}
	if len(result) != 1 || result[0].FindingID != "rf-1" {
		t.Fatalf("unexpected repo findings: %+v", result)
	}
}
