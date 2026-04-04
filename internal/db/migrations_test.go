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

func TestThirdMigrationContainsRepoScanTables(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000003_repo_scans.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	if !strings.Contains(text, "CREATE TABLE IF NOT EXISTS repo_scans") {
		t.Fatal("expected repo_scans table creation in third migration")
	}
	if !strings.Contains(text, "CREATE TABLE IF NOT EXISTS repo_findings") {
		t.Fatal("expected repo_findings table creation in third migration")
	}
}

func TestFourthMigrationContainsPerformanceIndexes(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000004_performance_indexes.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	required := []string{
		"idx_findings_scan_severity_type_created",
		"idx_findings_created_at",
		"idx_repo_findings_scan_severity_type_created",
		"idx_repo_findings_created_at",
		"idx_scan_events_scan_level_created",
	}
	for _, item := range required {
		if !strings.Contains(text, item) {
			t.Fatalf("expected performance index %q in fourth migration", item)
		}
	}
}

func TestSixthMigrationContainsTenantWorkspaceScope(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000006_tenant_workspace_scope.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	required := []string{
		"ADD COLUMN IF NOT EXISTS tenant_id",
		"ADD COLUMN IF NOT EXISTS workspace_id",
		"idx_scans_scope_started_at",
		"idx_repo_scans_scope_started_at",
	}
	for _, item := range required {
		if !strings.Contains(text, item) {
			t.Fatalf("expected tenant/workspace scope migration item %q", item)
		}
	}
}
