package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/identrailreviewer/model"
)

func TestReviewPRWritesOutput(t *testing.T) {
	root := t.TempDir()
	eventPath := filepath.Join(root, "event.json")
	changedPath := filepath.Join(root, "changed.json")
	outputPath := filepath.Join(root, "review.json")

	event := model.PullRequestEvent{
		PullRequest: model.PullRequest{
			Number: 77,
			Title:  "test pr",
			Body:   "### Summary\nok\n### Why\nok\n### Scope\nok\n### Validation\nok\n### Checklist\nok\n### AI Assistance Disclosure\nok\n### Related Issues\nok\n",
			Labels: []model.Label{{Name: "area/security"}},
		},
	}
	if err := writeJSONFile(eventPath, event); err != nil {
		t.Fatalf("write event json: %v", err)
	}
	if err := writeJSONFile(changedPath, []model.ChangedFile{}); err != nil {
		t.Fatalf("write changed files json: %v", err)
	}

	reviewPR([]string{
		"--repo-root", root,
		"--event-path", eventPath,
		"--changed-files", changedPath,
		"--output", outputPath,
	})

	var got model.ReviewResult
	if err := readJSONFile(outputPath, &got); err != nil {
		t.Fatalf("read output: %v", err)
	}
	if got.Target != "pull_request" {
		t.Fatalf("expected pull_request target, got %q", got.Target)
	}
	if got.Number != 77 {
		t.Fatalf("expected PR number 77, got %d", got.Number)
	}
}

func TestReviewIssueWritesOutput(t *testing.T) {
	root := t.TempDir()
	eventPath := filepath.Join(root, "event.json")
	outputPath := filepath.Join(root, "review.json")

	event := model.IssueEvent{
		Issue: model.Issue{
			Number: 88,
			Title:  "[feature]: add report",
			Body:   "### Problem statement\nx\n### Proposed solution\ny\n### Area\nz\n### User and operator impact\nlow\n### Acceptance criteria\ndone\n",
			Labels: []model.Label{{Name: "kind/enhancement"}},
		},
	}
	if err := writeJSONFile(eventPath, event); err != nil {
		t.Fatalf("write event json: %v", err)
	}

	reviewIssue([]string{
		"--event-path", eventPath,
		"--output", outputPath,
	})

	var got model.ReviewResult
	if err := readJSONFile(outputPath, &got); err != nil {
		t.Fatalf("read output: %v", err)
	}
	if got.Target != "issue" {
		t.Fatalf("expected issue target, got %q", got.Target)
	}
	if got.Number != 88 {
		t.Fatalf("expected issue number 88, got %d", got.Number)
	}
}

func TestWriteJSONWritesFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "out.json")
	writeJSON(path, map[string]string{"k": "v"})

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("expected non-empty output file")
	}
}

func writeJSONFile(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func readJSONFile(path string, out any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}
