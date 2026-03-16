package db

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitialMigrationContainsCoreTables(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000001_init.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)

	required := []string{
		"CREATE TABLE IF NOT EXISTS scans",
		"CREATE TABLE IF NOT EXISTS identities",
		"CREATE TABLE IF NOT EXISTS relationships",
		"CREATE TABLE IF NOT EXISTS findings",
		"PRIMARY KEY (scan_id, finding_id)",
	}

	for _, needle := range required {
		if !strings.Contains(text, needle) {
			t.Fatalf("expected migration to contain %q", needle)
		}
	}
}

func TestSecondMigrationContainsScanEvents(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000002_scan_events.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	if !strings.Contains(text, "CREATE TABLE IF NOT EXISTS scan_events") {
		t.Fatal("expected scan_events table creation in second migration")
	}
}
