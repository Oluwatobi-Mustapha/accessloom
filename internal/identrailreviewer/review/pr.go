package review

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Oluwatobi-Mustapha/identrail/internal/identrailreviewer/model"
)

func ReviewPR(repoRoot string, number int, title, body string, labels []string, changedFiles []model.ChangedFile) model.ReviewResult {
	findings := make([]model.Finding, 0)
	abstentions := make([]string, 0)

	for _, f := range changedFiles {
		if !isWorkflowFile(f.Filename) {
			continue
		}

		content, err := readFile(repoRoot, f.Filename)
		if err != nil {
			abstentions = append(abstentions, fmt.Sprintf("unable to inspect %s: %v", f.Filename, err))
			continue
		}

		if strings.Contains(content, "https://api.identrail.example") {
			findings = append(findings, model.Finding{
				ID:             "IR-PR-001",
				Severity:       "P1",
				Confidence:     0.98,
				RuleID:         "workflow/release-web-api-placeholder",
				Summary:        "Release web image uses placeholder production API URL",
				Rationale:      "Hardcoded example endpoints in release images can ship misconfigured production builds.",
				File:           f.Filename,
				Line:           lineOfSubstring(content, "https://api.identrail.example"),
				Recommendation: "Use a repository variable or workflow input to inject the real API URL and fail if unset.",
			})
		}

		if strings.Contains(content, `if [[ "${tag}" == *-* ]]`) && strings.Contains(content, `(\+[0-9A-Za-z.-]+)?$`) {
			findings = append(findings, model.Finding{
				ID:             "IR-PR-002",
				Severity:       "P2",
				Confidence:     0.91,
				RuleID:         "workflow/prerelease-detection-build-metadata",
				Summary:        "Prerelease detection may misclassify build-metadata tags",
				Rationale:      "Checking for '-' across the whole tag can classify stable tags with +build metadata incorrectly.",
				File:           f.Filename,
				Line:           lineOfSubstring(content, `if [[ "${tag}" == *-* ]]`),
				Recommendation: "Strip +build metadata before prerelease detection or match only semantic prerelease segment.",
			})
		}

		if !strings.Contains(content, "\npermissions:") && !strings.HasPrefix(content, "permissions:") {
			findings = append(findings, model.Finding{
				ID:             "IR-PR-003",
				Severity:       "P2",
				Confidence:     0.87,
				RuleID:         "workflow/missing-permissions-block",
				Summary:        "Workflow file does not declare explicit permissions",
				Rationale:      "Explicit permissions reduce token scope and limit blast radius during workflow execution.",
				File:           f.Filename,
				Line:           1,
				Recommendation: "Add a top-level permissions block with least-privilege scopes.",
			})
		}
	}

	sections := []string{
		"Summary",
		"Why",
		"Scope",
		"Validation",
		"Checklist",
		"AI Assistance Disclosure",
		"Related Issues",
	}
	for _, section := range sections {
		if !hasHeading(body, section) {
			findings = append(findings, model.Finding{
				ID:             fmt.Sprintf("IR-PR-004-%s", slugToken(section)),
				Severity:       "P3",
				Confidence:     0.84,
				RuleID:         "process/pr-template-missing-sections",
				Summary:        fmt.Sprintf("PR description missing required section: %s", section),
				Rationale:      "Consistent PR structure improves review quality, traceability, and change risk assessment.",
				File:           ".github/PULL_REQUEST_TEMPLATE.md",
				Line:           1,
				Recommendation: fmt.Sprintf("Update the PR body to include the '%s' section.", section),
			})
		}
	}

	status := "clean"
	summary := "No deterministic findings were detected."
	if len(findings) > 0 {
		status = "findings"
		summary = fmt.Sprintf("Detected %d deterministic finding(s) for review.", len(findings))
	}

	if len(findings) == 0 && len(abstentions) > 0 {
		status = "abstain"
		summary = "No deterministic findings; reviewer abstained on at least one check."
	}

	return model.ReviewResult{
		Reviewer: "identrail-reviewer",
		Version:  "0.2.0-week2",
		Mode:     "active",
		Target:   "pull_request",
		Number:   number,
		Status:   status,
		Summary:  summary,
		Findings: findings,
		Abstain:  abstentions,
		Metadata: map[string]string{
			"title":     title,
			"labels":    strings.Join(labels, ","),
			"fileCount": fmt.Sprintf("%d", len(changedFiles)),
		},
	}
}

func isWorkflowFile(path string) bool {
	if !strings.HasPrefix(path, ".github/workflows/") {
		return false
	}
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yml" || ext == ".yaml"
}
