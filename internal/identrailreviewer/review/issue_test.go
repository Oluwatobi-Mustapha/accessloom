package review

import "testing"

func TestReviewIssueBugTemplateAndSensitiveMaterial(t *testing.T) {
	result := ReviewIssue(
		33,
		"[bug]: api panic on startup",
		"### Area\napi\n\n### Version\nv1.2.3\n\naWS_SECRET_ACCESS_KEY = abc123",
		nil,
	)
	if result.Status != "findings" {
		t.Fatalf("expected findings status, got %q", result.Status)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings for incomplete bug template and sensitive material")
	}
}

func TestReviewIssueFeatureCleanByLabel(t *testing.T) {
	body := "" +
		"### Problem statement\nx\n" +
		"### Proposed solution\ny\n" +
		"### Area\nz\n" +
		"### User and operator impact\nlow\n" +
		"### Acceptance criteria\ndone\n"
	result := ReviewIssue(
		34,
		"Improve reporting",
		body,
		[]string{"kind/enhancement"},
	)
	if result.Status != "clean" {
		t.Fatalf("expected clean status, got %q", result.Status)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(result.Findings))
	}
}

func TestReviewIssueAbstainWhenTypeUnknown(t *testing.T) {
	result := ReviewIssue(35, "Question about docs", "body", []string{"question"})
	if result.Status != "abstain" {
		t.Fatalf("expected abstain status, got %q", result.Status)
	}
	if len(result.Abstain) == 0 {
		t.Fatal("expected abstention note")
	}
}
