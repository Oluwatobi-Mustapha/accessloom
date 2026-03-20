package standards

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
)

func TestFindingPayloadCompatibilitySnapshots(t *testing.T) {
	finding := domain.Finding{
		ID:           "compat-finding-1",
		ScanID:       "scan-compat-1",
		Type:         domain.FindingEscalationPath,
		Severity:     domain.SeverityCritical,
		Title:        "Escalation path to admin",
		HumanSummary: "A workload can escalate to administrator access.",
		Path:         []string{"aws:identity:role:payments", "aws:access:iam:*:*"},
		Evidence: map[string]any{
			"path_count": 1,
		},
		Remediation: "Remove wildcard trust and reduce permissions.",
		CreatedAt:   time.Date(2026, 3, 20, 8, 0, 0, 0, time.UTC),
	}

	enriched := EnrichFinding(finding)
	if enriched.Evidence["schema_version"] != "v1" {
		t.Fatalf("expected schema_version v1, got %v", enriched.Evidence["schema_version"])
	}

	ocsf := BuildOCSFAlignedExport(finding)
	asff := BuildASFFExport(finding, "", "", "")

	assertFindingSnapshot(t, "finding_enriched_compatibility", enriched)
	assertFindingSnapshot(t, "finding_ocsf_export_compatibility", ocsf)
	assertFindingSnapshot(t, "finding_asff_export_compatibility", asff)
}

func assertFindingSnapshot(t *testing.T, name string, payload any) {
	t.Helper()
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("marshal snapshot %s: %v", name, err)
	}
	data = append(data, '\n')
	path := findingSnapshotPath(t, name)
	if os.Getenv("UPDATE_CONTRACT_SNAPSHOTS") == "1" {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("write snapshot %s: %v", name, err)
		}
	}
	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read snapshot %s: %v", name, err)
	}
	if string(expected) != string(data) {
		t.Fatalf("snapshot mismatch for %s\nexpected:\n%s\nactual:\n%s", name, string(expected), string(data))
	}
}

func findingSnapshotPath(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	return filepath.Join(root, "testdata", "contracts", name+".snapshot.json")
}
