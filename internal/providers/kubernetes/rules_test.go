package kubernetes

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

func TestRuleSetDetectsOverprivilegedAndEscalation(t *testing.T) {
	normalizer := NewNormalizer()
	bundle, err := normalizer.Normalize(context.Background(), []providers.RawAsset{
		loadRawFixture(t, "k8s_service_account", "service_account_payments.json", "k8s:sa:apps:payments-api"),
		loadRawFixture(t, "k8s_role", "cluster_role_cluster_admin.json", "k8s:role:cluster:cluster-admin"),
		loadRawFixture(t, "k8s_role_binding", "role_binding_cluster_admin.json", "k8s:rb:cluster:payments-cluster-admin"),
		loadRawFixture(t, "k8s_pod", "pod_payments.json", "k8s:pod:apps:payments-api-0"),
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	perms, err := NewPermissionResolver().ResolvePermissions(context.Background(), bundle)
	if err != nil {
		t.Fatalf("resolve permissions failed: %v", err)
	}
	relationships, err := NewRelationshipResolver().ResolveRelationships(context.Background(), bundle, perms)
	if err != nil {
		t.Fatalf("resolve relationships failed: %v", err)
	}

	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	rules := NewRuleSet()
	rules.now = func() time.Time { return now }
	findings, err := rules.Evaluate(context.Background(), bundle, relationships)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}

	if !containsFindingType(findings, domain.FindingOverPrivileged) {
		t.Fatalf("expected overprivileged finding, got %v", findingTypes(findings))
	}
	if !containsFindingType(findings, domain.FindingEscalationPath) {
		t.Fatalf("expected escalation finding, got %v", findingTypes(findings))
	}
	if containsFindingType(findings, domain.FindingOwnerless) {
		t.Fatalf("did not expect ownerless finding for labeled service account")
	}
}

func TestRuleSetDetectsOwnerlessIdentity(t *testing.T) {
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	identity := domain.Identity{
		ID:       serviceAccountID("apps", "ownerless"),
		Provider: domain.ProviderKubernetes,
		Type:     domain.IdentityTypeServiceAccount,
		Name:     "apps/ownerless",
		ARN:      serviceAccountID("apps", "ownerless"),
	}
	bundle := providers.NormalizedBundle{Identities: []domain.Identity{identity}}
	rules := NewRuleSet()
	rules.now = func() time.Time { return now }

	findings, err := rules.Evaluate(context.Background(), bundle, nil)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if !containsFindingType(findings, domain.FindingOwnerless) {
		t.Fatalf("expected ownerless finding, got %v", findingTypes(findings))
	}
}

func TestRuleSetDeterministicIDs(t *testing.T) {
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	identity := domain.Identity{
		ID:        serviceAccountID("apps", "demo"),
		Provider:  domain.ProviderKubernetes,
		Type:      domain.IdentityTypeServiceAccount,
		Name:      "apps/demo",
		ARN:       serviceAccountID("apps", "demo"),
		OwnerHint: "team-a",
	}
	bundle := providers.NormalizedBundle{Identities: []domain.Identity{identity}}
	relationships := []domain.Relationship{
		{Type: domain.RelationshipCanAccess, FromNodeID: identity.ID, ToNodeID: accessNodeID("*", "*")},
	}
	rules := NewRuleSet()
	rules.now = func() time.Time { return now }

	first, err := rules.Evaluate(context.Background(), bundle, relationships)
	if err != nil {
		t.Fatalf("first evaluate failed: %v", err)
	}
	second, err := rules.Evaluate(context.Background(), bundle, relationships)
	if err != nil {
		t.Fatalf("second evaluate failed: %v", err)
	}

	if len(first) != len(second) {
		t.Fatalf("finding count mismatch %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].ID != second[i].ID {
			t.Fatalf("non-deterministic finding id at index %d: %q vs %q", i, first[i].ID, second[i].ID)
		}
	}
}

func TestRuleSetDeterministicEvidenceOrdering(t *testing.T) {
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	identity := domain.Identity{
		ID:        serviceAccountID("apps", "demo"),
		Provider:  domain.ProviderKubernetes,
		Type:      domain.IdentityTypeServiceAccount,
		Name:      "apps/demo",
		ARN:       serviceAccountID("apps", "demo"),
		OwnerHint: "team-a",
	}
	bundle := providers.NormalizedBundle{Identities: []domain.Identity{identity}}

	relationshipsA := []domain.Relationship{
		{Type: domain.RelationshipCanAccess, FromNodeID: identity.ID, ToNodeID: accessNodeID("create", "clusterrolebindings")},
		{Type: domain.RelationshipCanAccess, FromNodeID: identity.ID, ToNodeID: accessNodeID("*", "*")},
	}
	relationshipsB := []domain.Relationship{
		{Type: domain.RelationshipCanAccess, FromNodeID: identity.ID, ToNodeID: accessNodeID("*", "*")},
		{Type: domain.RelationshipCanAccess, FromNodeID: identity.ID, ToNodeID: accessNodeID("create", "clusterrolebindings")},
	}

	rules := NewRuleSet()
	rules.now = func() time.Time { return now }
	findingsA, err := rules.Evaluate(context.Background(), bundle, relationshipsA)
	if err != nil {
		t.Fatalf("evaluate A failed: %v", err)
	}
	findingsB, err := rules.Evaluate(context.Background(), bundle, relationshipsB)
	if err != nil {
		t.Fatalf("evaluate B failed: %v", err)
	}

	var overA, overB domain.Finding
	for _, finding := range findingsA {
		if finding.Type == domain.FindingOverPrivileged {
			overA = finding
			break
		}
	}
	for _, finding := range findingsB {
		if finding.Type == domain.FindingOverPrivileged {
			overB = finding
			break
		}
	}
	if overA.ID == "" || overB.ID == "" {
		t.Fatalf("missing overprivileged finding; got A=%v B=%v", findingTypes(findingsA), findingTypes(findingsB))
	}
	if !reflect.DeepEqual(overA.Evidence, overB.Evidence) {
		t.Fatalf("expected deterministic evidence ordering, got A=%+v B=%+v", overA.Evidence, overB.Evidence)
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

func TestParseAccessNode(t *testing.T) {
	action, resource, ok := parseAccessNode(accessNodeID("create", "clusterrolebindings"))
	if !ok {
		t.Fatal("expected parse success")
	}
	if action != "create" || resource != "clusterrolebindings" {
		t.Fatalf("unexpected parse values: action=%q resource=%q", action, resource)
	}
}

func TestSeveritySortOrder(t *testing.T) {
	now := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	identity := domain.Identity{
		ID:        serviceAccountID("apps", "demo"),
		Provider:  domain.ProviderKubernetes,
		Type:      domain.IdentityTypeServiceAccount,
		Name:      "apps/demo",
		ARN:       serviceAccountID("apps", "demo"),
		OwnerHint: "team-a",
	}
	bundle := providers.NormalizedBundle{
		Identities: []domain.Identity{
			identity,
		},
	}
	relationships := []domain.Relationship{
		{Type: domain.RelationshipBoundTo, FromNodeID: workloadID("apps", "demo-0"), ToNodeID: identity.ID},
		{Type: domain.RelationshipCanAccess, FromNodeID: identity.ID, ToNodeID: accessNodeID("*", "*")},
	}
	rules := NewRuleSet()
	rules.now = func() time.Time { return now }
	findings, err := rules.Evaluate(context.Background(), bundle, relationships)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}

	severities := make([]domain.FindingSeverity, 0, len(findings))
	for _, finding := range findings {
		severities = append(severities, finding.Severity)
	}
	criticalIndex := slices.Index(severities, domain.SeverityCritical)
	highIndex := slices.Index(severities, domain.SeverityHigh)
	if criticalIndex == -1 || highIndex == -1 || criticalIndex > highIndex {
		t.Fatalf("expected critical findings before high findings, got %+v", severities)
	}
}

func TestPermissionRiskHelpers(t *testing.T) {
	if !isOverprivilegedPermission("*", "*") {
		t.Fatal("expected wildcard permission to be overprivileged")
	}
	if !isOverprivilegedPermission("update", "clusterrolebindings") {
		t.Fatal("expected rbac update to be overprivileged")
	}
	if isOverprivilegedPermission("get", "pods") {
		t.Fatal("did not expect read-only pod access to be overprivileged")
	}
	if !isEscalationPermission("bind", "*") {
		t.Fatal("expected bind to be escalation-capable")
	}
	if isEscalationPermission("get", "pods") {
		t.Fatal("did not expect get pods to be escalation-capable")
	}
	if !hasEscalationRisk([]accessRisk{{Escalates: false}, {Escalates: true}}) {
		t.Fatal("expected escalation risk detection")
	}
}

func TestUtilityHelpers(t *testing.T) {
	deduped := dedupeStrings([]string{"a", "a", " b ", ""})
	if len(deduped) != 2 || deduped[0] != "a" || deduped[1] != "b" {
		t.Fatalf("unexpected deduped values %+v", deduped)
	}
	if severityRank(domain.SeverityCritical) >= severityRank(domain.SeverityHigh) {
		t.Fatal("expected critical rank to be higher priority than high")
	}
	idAB := findingID("a", "b")
	if idAB == findingID("a", "c") {
		t.Fatal("expected different ids for different finding parts")
	}
	if !strings.HasPrefix(idAB, "k8s:finding:") {
		t.Fatalf("expected k8s finding prefix, got %q", idAB)
	}
	if len(strings.TrimPrefix(idAB, "k8s:finding:")) != 64 {
		t.Fatalf("expected sha256 hash length 64, got id %q", idAB)
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
