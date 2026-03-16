package domain

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFindingJSONUsesSnakeCaseFields(t *testing.T) {
	finding := Finding{
		ID:           "f-1",
		ScanID:       "scan-1",
		Type:         FindingRiskyTrustPolicy,
		Severity:     SeverityHigh,
		Title:        "title",
		HumanSummary: "summary",
		Path:         []string{"node-a", "node-b"},
		Remediation:  "fix",
		CreatedAt:    time.Date(2026, 3, 16, 0, 0, 0, 0, time.UTC),
	}

	payload, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	text := string(payload)
	for _, expected := range []string{`"id"`, `"scan_id"`, `"human_summary"`, `"created_at"`} {
		if !strings.Contains(text, expected) {
			t.Fatalf("expected field %s in %s", expected, text)
		}
	}
	if strings.Contains(text, `"ScanID"`) || strings.Contains(text, `"HumanSummary"`) {
		t.Fatalf("unexpected struct field casing leaked in payload: %s", text)
	}
}

func TestIdentityJSONUsesSnakeCaseFields(t *testing.T) {
	identity := Identity{
		ID:        "id-1",
		Provider:  ProviderAWS,
		Type:      IdentityTypeRole,
		Name:      "payments-app",
		ARN:       "arn:aws:iam::123456789012:role/payments-app",
		OwnerHint: "team-security",
		CreatedAt: time.Date(2026, 3, 16, 0, 0, 0, 0, time.UTC),
		RawRef:    "ref-1",
	}

	payload, err := json.Marshal(identity)
	if err != nil {
		t.Fatalf("marshal identity: %v", err)
	}
	text := string(payload)
	for _, expected := range []string{`"id"`, `"owner_hint"`, `"created_at"`, `"raw_ref"`, `"arn"`} {
		if !strings.Contains(text, expected) {
			t.Fatalf("expected field %s in %s", expected, text)
		}
	}
	if strings.Contains(text, `"OwnerHint"`) || strings.Contains(text, `"RawRef"`) {
		t.Fatalf("unexpected struct field casing leaked in payload: %s", text)
	}
}
