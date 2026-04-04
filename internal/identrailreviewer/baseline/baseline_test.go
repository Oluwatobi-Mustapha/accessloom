package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/identrailreviewer/model"
)

func TestLoadEmptyPathReturnsOffMode(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load baseline with empty path: %v", err)
	}
	if cfg.Mode != modeOff {
		t.Fatalf("expected mode %q, got %q", modeOff, cfg.Mode)
	}
}

func TestLoadRejectsUnsupportedMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, []byte(`{"mode":"unsupported"}`), 0o600); err != nil {
		t.Fatalf("write baseline fixture: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected load to fail for unsupported mode")
	}
	if !strings.Contains(err.Error(), "unsupported mode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRejectsEmptyKnownFindingID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, []byte(`{"mode":"new-findings-only","known_finding_ids":[""]}`), 0o600); err != nil {
		t.Fatalf("write baseline fixture: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected load to fail for empty known finding ID")
	}
	if !strings.Contains(err.Error(), "known_finding_ids contains empty value") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadDefaultsModeWhenOmitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, []byte(`{"version":"v1","known_finding_ids":["IR-1"]}`), 0o600); err != nil {
		t.Fatalf("write baseline fixture: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	if cfg.Mode != modeNewFindingsOnly {
		t.Fatalf("expected default mode %q, got %q", modeNewFindingsOnly, cfg.Mode)
	}
}

func TestApplySuppressesKnownFindingIDs(t *testing.T) {
	result := model.ReviewResult{
		Status:  "findings",
		Summary: "Detected findings",
		Findings: []model.Finding{
			{ID: "IR-1", Summary: "known"},
			{ID: "IR-2", Summary: "new"},
		},
	}

	got := Apply(Config{
		Version:         "2026-04-05",
		Mode:            modeNewFindingsOnly,
		KnownFindingIDs: []string{"IR-1"},
	}, result)

	if len(got.Findings) != 1 {
		t.Fatalf("expected 1 remaining finding, got %d", len(got.Findings))
	}
	if got.Findings[0].ID != "IR-2" {
		t.Fatalf("expected remaining finding IR-2, got %q", got.Findings[0].ID)
	}
	if got.Metadata["baseline_suppressed_findings"] != "1" {
		t.Fatalf("expected baseline_suppressed_findings=1, got %q", got.Metadata["baseline_suppressed_findings"])
	}
	if got.Status != "findings" {
		t.Fatalf("expected findings status, got %q", got.Status)
	}
}

func TestApplyAllSuppressedMarksClean(t *testing.T) {
	result := model.ReviewResult{
		Status: "findings",
		Findings: []model.Finding{
			{ID: "IR-1"},
		},
	}

	got := Apply(Config{
		Mode:            modeNewFindingsOnly,
		KnownFindingIDs: []string{"IR-1"},
	}, result)

	if got.Status != "clean" {
		t.Fatalf("expected clean status after suppression, got %q", got.Status)
	}
	if len(got.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got.Findings))
	}
}

func TestApplyAllSuppressedWithAbstentionsMarksAbstain(t *testing.T) {
	result := model.ReviewResult{
		Status:  "findings",
		Abstain: []string{"unable to inspect file"},
		Findings: []model.Finding{
			{ID: "IR-1"},
		},
	}

	got := Apply(Config{
		Mode:            modeNewFindingsOnly,
		KnownFindingIDs: []string{"IR-1"},
	}, result)

	if got.Status != "abstain" {
		t.Fatalf("expected abstain status after suppression with abstentions, got %q", got.Status)
	}
}

func TestApplyWithNoKnownEntriesSetsSuppressedZero(t *testing.T) {
	result := model.ReviewResult{
		Status: "findings",
		Findings: []model.Finding{
			{ID: "IR-1"},
		},
	}

	got := Apply(Config{
		Mode:            modeNewFindingsOnly,
		KnownFindingIDs: nil,
	}, result)

	if got.Metadata["baseline_suppressed_findings"] != "0" {
		t.Fatalf("expected baseline_suppressed_findings=0, got %q", got.Metadata["baseline_suppressed_findings"])
	}
}

func TestApplyOffModeLeavesResultUnchanged(t *testing.T) {
	result := model.ReviewResult{
		Status: "findings",
		Findings: []model.Finding{
			{ID: "IR-1"},
		},
	}

	got := Apply(Config{
		Mode:            modeOff,
		KnownFindingIDs: []string{"IR-1"},
	}, result)

	if got.Status != "findings" {
		t.Fatalf("expected findings status, got %q", got.Status)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got.Findings))
	}
}
