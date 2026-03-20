package db

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestMigrationFiles(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "0002_add.up.sql"), []byte("SELECT 2;"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "0001_init.up.sql"), []byte("SELECT 1;"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "0001_init.down.sql"), []byte("DROP TABLE x;"), 0o600)

	files, err := migrationFiles(dir)
	if err != nil {
		t.Fatalf("migrationFiles failed: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(files))
	}
	if filepath.Base(files[0]) != "0001_init.up.sql" {
		t.Fatalf("expected sorted file order, got %s", files[0])
	}

	downFiles, err := downMigrationFiles(dir)
	if err != nil {
		t.Fatalf("downMigrationFiles failed: %v", err)
	}
	if len(downFiles) != 1 {
		t.Fatalf("expected 1 down file, got %d", len(downFiles))
	}
	if filepath.Base(downFiles[0]) != "0001_init.down.sql" {
		t.Fatalf("expected reverse-sorted down file order, got %s", downFiles[0])
	}
}

func TestApplyMigrations(t *testing.T) {
	dir := t.TempDir()
	query := "SELECT 1;"
	if err := os.WriteFile(filepath.Join(dir, "0001_init.up.sql"), []byte(query), 0o600); err != nil {
		t.Fatalf("write migration: %v", err)
	}

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectExec(regexp.QuoteMeta(query)).WillReturnResult(sqlmock.NewResult(0, 0))

	if err := ApplyMigrations(context.Background(), db, dir); err != nil {
		t.Fatalf("apply migrations failed: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestApplyDownMigrations(t *testing.T) {
	dir := t.TempDir()
	queryOne := "SELECT 1;"
	queryTwo := "SELECT 2;"
	if err := os.WriteFile(filepath.Join(dir, "0001_init.down.sql"), []byte(queryOne), 0o600); err != nil {
		t.Fatalf("write migration: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "0002_add.down.sql"), []byte(queryTwo), 0o600); err != nil {
		t.Fatalf("write migration: %v", err)
	}

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	// Down migrations are applied in reverse lexical order.
	mock.ExpectExec(regexp.QuoteMeta(queryTwo)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(queryOne)).WillReturnResult(sqlmock.NewResult(0, 0))

	if err := ApplyDownMigrations(context.Background(), db, dir); err != nil {
		t.Fatalf("apply down migrations failed: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestApplyMigrationsNoFiles(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	err = ApplyMigrations(context.Background(), db, t.TempDir())
	if err == nil {
		t.Fatal("expected error when no migration files")
	}
}

func TestPostgresStoreApplyMigrationsNilStore(t *testing.T) {
	store := &PostgresStore{}
	err := store.ApplyMigrations(context.Background(), "migrations")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNewPostgresStoreWithDBApplyMigrations(t *testing.T) {
	dir := t.TempDir()
	query := "SELECT 1;"
	if err := os.WriteFile(filepath.Join(dir, "0001_init.up.sql"), []byte(query), 0o600); err != nil {
		t.Fatalf("write migration: %v", err)
	}

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	mock.ExpectExec(regexp.QuoteMeta(query)).WillReturnResult(sqlmock.NewResult(0, 0))

	if err := store.ApplyMigrations(context.Background(), dir); err != nil {
		t.Fatalf("apply migrations failed: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestNewPostgresStoreWithDBApplyDownMigrations(t *testing.T) {
	dir := t.TempDir()
	query := "SELECT 1;"
	if err := os.WriteFile(filepath.Join(dir, "0001_init.down.sql"), []byte(query), 0o600); err != nil {
		t.Fatalf("write migration: %v", err)
	}

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	store := NewPostgresStoreWithDB(db)
	mock.ExpectExec(regexp.QuoteMeta(query)).WillReturnResult(sqlmock.NewResult(0, 0))

	if err := store.ApplyDownMigrations(context.Background(), dir); err != nil {
		t.Fatalf("apply down migrations failed: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestApplyMigrationsWithNilDB(t *testing.T) {
	err := ApplyMigrations(context.Background(), (*sql.DB)(nil), t.TempDir())
	if err == nil {
		t.Fatal("expected error for nil db")
	}
}

func TestApplyDownMigrationsWithNilDB(t *testing.T) {
	err := ApplyDownMigrations(context.Background(), (*sql.DB)(nil), t.TempDir())
	if err == nil {
		t.Fatal("expected error for nil db")
	}
}
