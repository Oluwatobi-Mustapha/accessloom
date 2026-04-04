package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/identrailreviewer/model"
)

func TestAppendNoopWhenPathEmpty(t *testing.T) {
	if err := Append("", model.ReviewResult{}); err != nil {
		t.Fatalf("append with empty path should be a no-op: %v", err)
	}
}

func TestAppendWritesAuditEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit", "events.jsonl")
	result := model.ReviewResult{
		Reviewer: "identrail-reviewer",
		Version:  "0.3.0",
		Target:   "pr",
		Number:   74,
		Status:   "findings",
		Findings: []model.Finding{
			{ID: "F-1", RuleID: "rule-a", Severity: "P1", Confidence: 0.91, File: "a.go", Line: 10},
		},
		Abstain: []string{"suppressed low confidence"},
		Metadata: map[string]string{
			"policy_version": "policy.v1",
		},
	}

	if err := Append(path, result); err != nil {
		t.Fatalf("append audit entry: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}

	var entry Entry
	if err := json.Unmarshal(content, &entry); err != nil {
		t.Fatalf("unmarshal audit entry: %v", err)
	}

	if entry.Reviewer != result.Reviewer {
		t.Fatalf("reviewer mismatch: got %q want %q", entry.Reviewer, result.Reviewer)
	}
	if entry.Version != result.Version {
		t.Fatalf("version mismatch: got %q want %q", entry.Version, result.Version)
	}
	if entry.Target != result.Target {
		t.Fatalf("target mismatch: got %q want %q", entry.Target, result.Target)
	}
	if entry.Number != result.Number {
		t.Fatalf("number mismatch: got %d want %d", entry.Number, result.Number)
	}
	if entry.Status != result.Status {
		t.Fatalf("status mismatch: got %q want %q", entry.Status, result.Status)
	}
	if entry.FindingCount != len(result.Findings) {
		t.Fatalf("finding count mismatch: got %d want %d", entry.FindingCount, len(result.Findings))
	}
	if entry.AbstentionCount != len(result.Abstain) {
		t.Fatalf("abstention count mismatch: got %d want %d", entry.AbstentionCount, len(result.Abstain))
	}
	if entry.PolicyVersion != "policy.v1" {
		t.Fatalf("policy version mismatch: got %q", entry.PolicyVersion)
	}
	if len(entry.Fingerprint) != 64 {
		t.Fatalf("fingerprint should be 64 hex chars, got %d", len(entry.Fingerprint))
	}
	if _, err := time.Parse(time.RFC3339, entry.Timestamp); err != nil {
		t.Fatalf("timestamp should be RFC3339: %v", err)
	}
}

func TestFindingFingerprintDeterministic(t *testing.T) {
	findings := []model.Finding{
		{ID: "F-1", RuleID: "rule-a", Severity: "P1", Confidence: 0.91, File: "a.go", Line: 10},
		{ID: "F-2", RuleID: "rule-b", Severity: "P2", Confidence: 0.88, File: "b.go", Line: 22},
	}

	first, err := findingFingerprint(findings)
	if err != nil {
		t.Fatalf("first fingerprint: %v", err)
	}
	second, err := findingFingerprint(findings)
	if err != nil {
		t.Fatalf("second fingerprint: %v", err)
	}
	if first != second {
		t.Fatalf("fingerprints must be deterministic: %q != %q", first, second)
	}
}
