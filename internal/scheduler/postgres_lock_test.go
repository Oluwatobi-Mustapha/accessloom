package scheduler

import (
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestPostgresAdvisoryLockerTryAcquireAndRelease(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	locker := NewPostgresAdvisoryLocker(db)
	lockID := advisoryLockID("identrail:scan:aws")

	mock.ExpectQuery(regexp.QuoteMeta("SELECT pg_try_advisory_lock($1)")).
		WithArgs(lockID).
		WillReturnRows(sqlmock.NewRows([]string{"pg_try_advisory_lock"}).AddRow(true))
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_unlock($1)")).
		WithArgs(lockID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	release, ok := locker.TryAcquire("identrail:scan:aws")
	if !ok || release == nil {
		t.Fatal("expected advisory lock to be acquired")
	}
	release()
	// Ensure release is idempotent.
	release()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestPostgresAdvisoryLockerTryAcquireFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	locker := NewPostgresAdvisoryLocker(db)
	lockID := advisoryLockID("identrail:scan:aws")
	mock.ExpectQuery(regexp.QuoteMeta("SELECT pg_try_advisory_lock($1)")).
		WithArgs(lockID).
		WillReturnRows(sqlmock.NewRows([]string{"pg_try_advisory_lock"}).AddRow(false))

	release, ok := locker.TryAcquire("identrail:scan:aws")
	if ok || release != nil {
		t.Fatal("expected lock acquisition failure")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestAdvisoryLockIDStability(t *testing.T) {
	first := advisoryLockID("identrail:scan:aws")
	second := advisoryLockID("identrail:scan:aws")
	if first != second {
		t.Fatal("expected stable lock id for same key")
	}
}

func TestPostgresAdvisoryLockerTryAcquireWithNilDB(t *testing.T) {
	locker := NewPostgresAdvisoryLocker(nil)
	release, ok := locker.TryAcquire("scan:aws")
	if ok || release != nil {
		t.Fatal("expected nil db locker to fail acquisition")
	}
}
