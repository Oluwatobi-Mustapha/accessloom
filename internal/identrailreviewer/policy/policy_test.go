package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/identrailreviewer/model"
)

func TestApplyUnknownRequiredFieldFailsClosed(t *testing.T) {
	cfg := defaultConfig()
	cfg.RequiredFields = append(cfg.RequiredFields, "recomendation")

	result := Apply(cfg, model.ReviewResult{
		Findings: []model.Finding{validFinding()},
	})

	if len(result.Findings) != 0 {
		t.Fatalf("expected finding to be suppressed for unknown required field, got %d findings", len(result.Findings))
	}
	if result.Status != "abstain" {
		t.Fatalf("expected status abstain, got %q", result.Status)
	}
}

func TestApplyNormalizesRequiredFieldNames(t *testing.T) {
	cfg := defaultConfig()
	cfg.RequiredFields = []string{
		" ID ",
		"Severity",
		"CONFIDENCE",
		"Rule_ID",
		"Summary",
		"Rationale",
		"File",
		"Line",
		"Recommendation",
	}

	result := Apply(cfg, model.ReviewResult{
		Findings: []model.Finding{validFinding()},
	})

	if len(result.Findings) != 1 {
		t.Fatalf("expected finding to remain after normalized required fields, got %d", len(result.Findings))
	}
	if result.Status != "findings" {
		t.Fatalf("expected status findings, got %q", result.Status)
	}
}

func TestLoadRejectsUnknownRequiredField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	content := `{
		"required_fields": ["id", "recomendation"]
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy fixture: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected load to fail for unknown required field")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown field validation error, got %v", err)
	}
}

func validFinding() model.Finding {
	return model.Finding{
		ID:             "F-1",
		Severity:       "P1",
		Confidence:     0.99,
		RuleID:         "rule",
		Summary:        "summary",
		Rationale:      "rationale",
		File:           "file.go",
		Line:           12,
		Recommendation: "fix",
	}
}
