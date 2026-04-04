package review

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/identrailreviewer/model"
)

func TestReviewPRDetectsWorkflowAndTemplateFindings(t *testing.T) {
	t.Helper()
	repoRoot := t.TempDir()
	workflowPath := filepath.Join(repoRoot, ".github", "workflows", "release.yml")
	if err := writeFile(workflowPath, strings.Join([]string{
		"name: release",
		"on:",
		"  push:",
		"    tags:",
		"      - v*",
		"jobs:",
		"  release:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		`      - run: echo "https://api.identrail.example"`,
		`      - run: |`,
		`          if [[ "${tag}" == *-* ]]; then`,
		`            echo "${tag}" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'`,
		"          fi",
	}, "\n")); err != nil {
		t.Fatalf("write workflow fixture: %v", err)
	}

	result := ReviewPR(
		repoRoot,
		101,
		"Week2 reviewer PR",
		"### Summary\n",
		[]string{"area/security"},
		[]model.ChangedFile{
			{Filename: ".github/workflows/release.yml", Status: "modified"},
			{Filename: "README.md", Status: "modified"},
		},
	)

	if result.Status != "findings" {
		t.Fatalf("expected findings status, got %q", result.Status)
	}
	if len(result.Findings) < 4 {
		t.Fatalf("expected multiple findings, got %d", len(result.Findings))
	}
	if result.Metadata["fileCount"] != "2" {
		t.Fatalf("expected fileCount=2, got %q", result.Metadata["fileCount"])
	}

	wantRules := map[string]bool{
		"workflow/release-web-api-placeholder":         false,
		"workflow/prerelease-detection-build-metadata": false,
		"workflow/missing-permissions-block":           false,
		"process/pr-template-missing-sections":         false,
	}
	for _, finding := range result.Findings {
		if _, ok := wantRules[finding.RuleID]; ok {
			wantRules[finding.RuleID] = true
		}
	}
	for ruleID, seen := range wantRules {
		if !seen {
			t.Fatalf("expected finding for rule %q", ruleID)
		}
	}
}

func TestReviewPRAbstainsOnUnreadableWorkflow(t *testing.T) {
	result := ReviewPR(
		t.TempDir(),
		102,
		"Week2 reviewer PR",
		fullPRTemplateBody(),
		nil,
		[]model.ChangedFile{
			{Filename: ".github/workflows/missing.yml", Status: "modified"},
		},
	)
	if result.Status != "abstain" {
		t.Fatalf("expected abstain status, got %q", result.Status)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(result.Findings))
	}
	if len(result.Abstain) == 0 {
		t.Fatal("expected abstention note")
	}
}

func TestIsWorkflowFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{path: ".github/workflows/build.yml", want: true},
		{path: ".github/workflows/build.yaml", want: true},
		{path: ".github/workflows/build.txt", want: false},
		{path: "deploy/workflows/build.yml", want: false},
	}
	for _, tc := range cases {
		if got := isWorkflowFile(tc.path); got != tc.want {
			t.Fatalf("isWorkflowFile(%q)=%t want %t", tc.path, got, tc.want)
		}
	}
}

func fullPRTemplateBody() string {
	return strings.Join([]string{
		"### Summary",
		"ok",
		"### Why",
		"ok",
		"### Scope",
		"ok",
		"### Validation",
		"ok",
		"### Checklist",
		"ok",
		"### AI Assistance Disclosure",
		"ok",
		"### Related Issues",
		"ok",
	}, "\n")
}
