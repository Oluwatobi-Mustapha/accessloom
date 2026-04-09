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

func TestFifthMigrationContainsFindingWorkflowTables(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000005_finding_workflow_maturity.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	required := []string{
		"CREATE TABLE IF NOT EXISTS finding_triage_states",
		"CREATE TABLE IF NOT EXISTS finding_triage_events",
		"idx_finding_triage_states_status",
		"idx_finding_triage_events_finding_created",
	}
	for _, item := range required {
		if !strings.Contains(text, item) {
			t.Fatalf("expected workflow migration to contain %q", item)
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

func TestSeventhMigrationContainsScopedTriageGuardrails(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000007_scope_guardrails_for_triage.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	required := []string{
		"ADD COLUMN IF NOT EXISTS tenant_id",
		"ADD COLUMN IF NOT EXISTS workspace_id",
		"PRIMARY KEY (tenant_id, workspace_id, finding_id)",
		"idx_finding_triage_states_scope_status",
		"idx_finding_triage_events_scope_finding_created",
	}
	for _, item := range required {
		if !strings.Contains(text, item) {
			t.Fatalf("expected scoped triage migration item %q", item)
		}
	}
}

func TestEighthMigrationContainsPostgresRLSGuardrails(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000008_postgres_rls_scope_guardrails.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	required := []string{
		"CREATE OR REPLACE FUNCTION identrail_rls_scope_matches",
		"ALTER TABLE scans ENABLE ROW LEVEL SECURITY",
		"CREATE POLICY scans_scope_isolation",
		"CREATE POLICY repo_scans_scope_isolation",
		"CREATE POLICY finding_triage_states_scope_isolation",
	}
	for _, item := range required {
		if !strings.Contains(text, item) {
			t.Fatalf("expected postgres rls migration item %q", item)
		}
	}
}

func TestNinthMigrationContainsAuthzABACAndReBACDataTables(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000009_authz_abac_rebac_data.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	required := []string{
		"CREATE TABLE IF NOT EXISTS authz_entity_attributes",
		"CREATE TABLE IF NOT EXISTS authz_relationships",
		"idx_authz_entity_attributes_scope_kind_type",
		"idx_authz_relationships_scope_subject_relation",
		"CREATE POLICY authz_entity_attributes_scope_isolation",
		"CREATE POLICY authz_relationships_scope_isolation",
	}
	for _, item := range required {
		if !strings.Contains(text, item) {
			t.Fatalf("expected authz data migration item %q", item)
		}
	}
}

func TestTenthMigrationContainsAuthzPolicyLifecycleTables(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "000010_authz_policy_lifecycle_controls.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(content)
	required := []string{
		"CREATE TABLE IF NOT EXISTS authz_policy_sets",
		"CREATE TABLE IF NOT EXISTS authz_policy_versions",
		"CREATE TABLE IF NOT EXISTS authz_policy_rollouts",
		"CREATE TABLE IF NOT EXISTS authz_policy_events",
		"idx_authz_policy_versions_scope_set_created",
		"idx_authz_policy_rollouts_scope_mode",
		"idx_authz_policy_events_scope_set_created",
		"FORCE ROW LEVEL SECURITY",
		"DROP POLICY IF EXISTS authz_policy_sets_scope_isolation",
		"DROP POLICY IF EXISTS authz_policy_versions_scope_isolation",
		"DROP POLICY IF EXISTS authz_policy_rollouts_scope_isolation",
		"DROP POLICY IF EXISTS authz_policy_events_scope_isolation",
		"CREATE POLICY authz_policy_sets_scope_isolation",
		"CREATE POLICY authz_policy_versions_scope_isolation",
		"CREATE POLICY authz_policy_rollouts_scope_isolation",
		"CREATE POLICY authz_policy_events_scope_isolation",
	}
	for _, item := range required {
		if !strings.Contains(text, item) {
			t.Fatalf("expected authz policy lifecycle migration item %q", item)
		}
	}
}
