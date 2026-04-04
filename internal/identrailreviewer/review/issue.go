package review

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Oluwatobi-Mustapha/identrail/internal/identrailreviewer/model"
)

func ReviewIssue(number int, title, body string, labels []string) model.ReviewResult {
	findings := make([]model.Finding, 0)
	abstentions := make([]string, 0)

	isBug := strings.HasPrefix(strings.ToLower(strings.TrimSpace(title)), "[bug]:") || hasLabel(labels, "kind/bug")
	isFeature := strings.HasPrefix(strings.ToLower(strings.TrimSpace(title)), "[feature]:") || hasLabel(labels, "kind/enhancement")

	if isBug {
		required := []string{"Area", "Version", "Environment", "Steps to reproduce", "Expected behavior", "Actual behavior", "Impact"}
		for _, heading := range required {
			if !hasHeading(body, heading) {
				findings = append(findings, model.Finding{
					ID:             fmt.Sprintf("IR-IS-001-%s", slugToken(heading)),
					Severity:       "P3",
					Confidence:     0.88,
					RuleID:         "issue/bug-template-completeness",
					Summary:        fmt.Sprintf("Bug issue is missing required field: %s", heading),
					Rationale:      "Missing bug context slows triage and increases misclassification risk.",
					File:           ".github/ISSUE_TEMPLATE/bug_report.yml",
					Line:           1,
					Recommendation: fmt.Sprintf("Edit the issue to include a populated '%s' section.", heading),
				})
			}
		}
	}

	if isFeature {
		required := []string{"Problem statement", "Proposed solution", "Area", "User and operator impact", "Acceptance criteria"}
		for _, heading := range required {
			if !hasHeading(body, heading) {
				findings = append(findings, model.Finding{
					ID:             fmt.Sprintf("IR-IS-002-%s", slugToken(heading)),
					Severity:       "P3",
					Confidence:     0.88,
					RuleID:         "issue/feature-template-completeness",
					Summary:        fmt.Sprintf("Feature issue is missing required field: %s", heading),
					Rationale:      "Feature requests need clear framing to support prioritization and design review.",
					File:           ".github/ISSUE_TEMPLATE/feature_request.yml",
					Line:           1,
					Recommendation: fmt.Sprintf("Edit the issue to include a populated '%s' section.", heading),
				})
			}
		}
	}

	if !isBug && !isFeature {
		abstentions = append(abstentions, "issue type could not be confidently inferred from title or labels")
	}

	sensitivePattern := regexp.MustCompile(`(?i)(aws_access_key_id|aws_secret_access_key|-----BEGIN [A-Z ]+PRIVATE KEY-----|token\s*[:=]|password\s*[:=])`)
	if sensitivePattern.MatchString(body) {
		findings = append(findings, model.Finding{
			ID:             "IR-IS-003",
			Severity:       "P1",
			Confidence:     0.90,
			RuleID:         "issue/public-sensitive-material",
			Summary:        "Issue body may include sensitive material",
			Rationale:      "Public issues should not contain credentials, tokens, or private keys.",
			File:           "ISSUE_BODY",
			Line:           lineOfRegex(body, sensitivePattern),
			Recommendation: "Redact sensitive values immediately and report vulnerabilities privately via SECURITY.md.",
		})
	}

	status := "clean"
	summary := "No deterministic triage findings were detected."
	if len(findings) > 0 {
		status = "findings"
		summary = fmt.Sprintf("Detected %d issue triage finding(s).", len(findings))
	}
	if len(findings) == 0 && len(abstentions) > 0 {
		status = "abstain"
		summary = "No deterministic findings; reviewer abstained on issue-type classification."
	}

	return model.ReviewResult{
		Reviewer: "identrail-reviewer",
		Version:  "0.2.0-week2",
		Mode:     "active",
		Target:   "issue",
		Number:   number,
		Status:   status,
		Summary:  summary,
		Findings: findings,
		Abstain:  abstentions,
		Metadata: map[string]string{
			"title":  title,
			"labels": strings.Join(labels, ","),
		},
	}
}
