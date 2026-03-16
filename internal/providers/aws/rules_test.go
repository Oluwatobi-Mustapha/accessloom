package aws

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

func TestRuleSetDetectsAllPrimaryRiskTypes(t *testing.T) {
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	lastUsed := now.Add(-120 * 24 * time.Hour)
	identity := domain.Identity{
		ID:         identityIDFromARN("arn:aws:iam::123456789012:role/admin-app"),
		Provider:   domain.ProviderAWS,
		Type:       domain.IdentityTypeRole,
		Name:       "admin-app",
		ARN:        "arn:aws:iam::123456789012:role/admin-app",
		CreatedAt:  now.Add(-400 * 24 * time.Hour),
		LastUsedAt: &lastUsed,
	}

	bundle := providers.NormalizedBundle{Identities: []domain.Identity{identity}}
	relationships := []domain.Relationship{
		{Type: domain.RelationshipCanAssume, FromNodeID: "aws:principal:*", ToNodeID: identity.ID},
		{Type: domain.RelationshipCanAccess, FromNodeID: identity.ID, ToNodeID: accessNodeID("iam:*", "*")},
	}

	rules := NewRuleSet(WithRuleClock(func() time.Time { return now }))
	findings, err := rules.Evaluate(context.Background(), bundle, relationships)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}

	types := map[domain.FindingType]bool{}
	for _, finding := range findings {
		types[finding.Type] = true
	}

	expected := []domain.FindingType{
		domain.FindingOwnerless,
		domain.FindingStaleIdentity,
		domain.FindingOverPrivileged,
		domain.FindingRiskyTrustPolicy,
		domain.FindingEscalationPath,
	}
	for _, findingType := range expected {
		if !types[findingType] {
			t.Fatalf("expected finding type %s", findingType)
		}
	}
}

func TestRuleSetFixturePipelineDetectsCrossAccountTrust(t *testing.T) {
	normalizer := NewRoleNormalizer()
	bundle, err := normalizer.Normalize(context.Background(), []providers.RawAsset{loadRawRoleAssetFixture(t, "role_with_policies.json")})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}

	permissions, err := NewPolicyPermissionResolver().ResolvePermissions(context.Background(), bundle)
	if err != nil {
		t.Fatalf("resolve permissions failed: %v", err)
	}

	relationships, err := NewRelationshipBuilder().ResolveRelationships(context.Background(), bundle, permissions)
	if err != nil {
		t.Fatalf("resolve relationships failed: %v", err)
	}

	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	findings, err := NewRuleSet(WithRuleClock(func() time.Time { return now })).Evaluate(context.Background(), bundle, relationships)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}

	if !containsFindingType(findings, domain.FindingRiskyTrustPolicy) {
		t.Fatalf("expected risky trust finding, got %+v", findingTypes(findings))
	}
	if containsFindingType(findings, domain.FindingOverPrivileged) {
		t.Fatalf("did not expect overprivileged finding for fixture role")
	}
}

func TestRuleSetContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := NewRuleSet().Evaluate(ctx, providers.NormalizedBundle{}, nil)
	if err == nil {
		t.Fatal("expected context error")
	}
}

func TestRuleSetDeterministicIDs(t *testing.T) {
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	identity := domain.Identity{
		ID:       identityIDFromARN("arn:aws:iam::123456789012:role/demo"),
		Provider: domain.ProviderAWS,
		Type:     domain.IdentityTypeRole,
		ARN:      "arn:aws:iam::123456789012:role/demo",
		Name:     "demo",
	}
	bundle := providers.NormalizedBundle{Identities: []domain.Identity{identity}}
	relationships := []domain.Relationship{{
		Type:       domain.RelationshipCanAccess,
		FromNodeID: identity.ID,
		ToNodeID:   accessNodeID("iam:*", "*"),
	}}

	rules := NewRuleSet(WithRuleClock(func() time.Time { return now }))
	first, err := rules.Evaluate(context.Background(), bundle, relationships)
	if err != nil {
		t.Fatalf("first evaluate failed: %v", err)
	}
	second, err := rules.Evaluate(context.Background(), bundle, relationships)
	if err != nil {
		t.Fatalf("second evaluate failed: %v", err)
	}

	if len(first) != len(second) {
		t.Fatalf("finding counts differ: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].ID != second[i].ID {
			t.Fatalf("non-deterministic ID at index %d: %s vs %s", i, first[i].ID, second[i].ID)
		}
	}
}

func TestParseAccessNode(t *testing.T) {
	action, resource, ok := parseAccessNode(accessNodeID("s3:GetObject", "arn:aws:s3:::bucket/*"))
	if !ok {
		t.Fatal("expected parse success")
	}
	if action != "s3:GetObject" || resource != "arn:aws:s3:::bucket/*" {
		t.Fatalf("unexpected parse values: %q %q", action, resource)
	}
}

func TestAccountIDFromARN(t *testing.T) {
	if got := accountIDFromARN("arn:aws:iam::123456789012:role/demo"); got != "123456789012" {
		t.Fatalf("unexpected account id: %q", got)
	}
	if got := accountIDFromARN("invalid"); got != "" {
		t.Fatalf("expected empty account id, got %q", got)
	}
}

func TestSeveritySortOrder(t *testing.T) {
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	identity := domain.Identity{
		ID:       identityIDFromARN("arn:aws:iam::123456789012:role/admin-app"),
		Provider: domain.ProviderAWS,
		Type:     domain.IdentityTypeRole,
		ARN:      "arn:aws:iam::123456789012:role/admin-app",
		Name:     "admin-app",
	}

	bundle := providers.NormalizedBundle{Identities: []domain.Identity{identity}}
	relationships := []domain.Relationship{
		{Type: domain.RelationshipCanAssume, FromNodeID: "aws:principal:*", ToNodeID: identity.ID},
		{Type: domain.RelationshipCanAccess, FromNodeID: identity.ID, ToNodeID: accessNodeID("iam:*", "*")},
	}

	findings, err := NewRuleSet(WithRuleClock(func() time.Time { return now })).Evaluate(context.Background(), bundle, relationships)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("expected multiple findings, got %d", len(findings))
	}

	severities := make([]domain.FindingSeverity, 0, len(findings))
	for _, finding := range findings {
		severities = append(severities, finding.Severity)
	}
	criticalIndex := slices.Index(severities, domain.SeverityCritical)
	highIndex := slices.Index(severities, domain.SeverityHigh)
	if criticalIndex == -1 || highIndex == -1 || criticalIndex > highIndex {
		t.Fatalf("expected critical findings before high findings, got order %+v", severities)
	}
}

func containsFindingType(findings []domain.Finding, findingType domain.FindingType) bool {
	for _, finding := range findings {
		if finding.Type == findingType {
			return true
		}
	}
	return false
}

func findingTypes(findings []domain.Finding) []domain.FindingType {
	types := make([]domain.FindingType, 0, len(findings))
	for _, finding := range findings {
		types = append(types, finding.Type)
	}
	return types
}
