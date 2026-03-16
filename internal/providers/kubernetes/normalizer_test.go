package kubernetes

import (
	"context"
	"strings"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

func TestNormalizerNormalizeFromFixtures(t *testing.T) {
	normalizer := NewNormalizer()
	raw := []providers.RawAsset{
		loadRawFixture(t, "k8s_service_account", "service_account_payments.json", "k8s:sa:apps:payments-api"),
		loadRawFixture(t, "k8s_role_binding", "role_binding_cluster_admin.json", "k8s:rb:cluster:payments-cluster-admin"),
		loadRawFixture(t, "k8s_pod", "pod_payments.json", "k8s:pod:apps:payments-api-0"),
	}

	bundle, err := normalizer.Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if len(bundle.Identities) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(bundle.Identities))
	}
	if got := bundle.Identities[0].OwnerHint; got != "payments" {
		t.Fatalf("unexpected owner hint %q", got)
	}
	if len(bundle.Workloads) != 1 {
		t.Fatalf("expected 1 workload, got %d", len(bundle.Workloads))
	}
	if bundle.Workloads[0].RawRef != bundle.Identities[0].ID {
		t.Fatalf("expected workload to reference identity id, got %q", bundle.Workloads[0].RawRef)
	}
	if len(bundle.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(bundle.Policies))
	}
	if bundle.Policies[0].Normalized[identityIDKey] != bundle.Identities[0].ID {
		t.Fatalf("policy identity link mismatch: %+v", bundle.Policies[0].Normalized)
	}
}

func TestNormalizerSkipsUnsupportedAndDeduplicates(t *testing.T) {
	normalizer := NewNormalizer()
	sa := loadRawFixture(t, "k8s_service_account", "service_account_payments.json", "k8s:sa:apps:payments-api")
	bundle, err := normalizer.Normalize(context.Background(), []providers.RawAsset{
		{Kind: "unknown", SourceID: "noop", Payload: []byte("{}")},
		sa,
		sa,
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if len(bundle.Identities) != 1 {
		t.Fatalf("expected deduplicated identity count 1, got %d", len(bundle.Identities))
	}
}

func TestNormalizerInvalidPayload(t *testing.T) {
	normalizer := NewNormalizer()
	_, err := normalizer.Normalize(context.Background(), []providers.RawAsset{
		{Kind: "k8s_service_account", Payload: []byte("not-json")},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "decode service account") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStatementsForRole(t *testing.T) {
	if got := len(statementsForRole("cluster-admin")); got != 1 {
		t.Fatalf("expected statement for cluster-admin, got %d", got)
	}
	if got := len(statementsForRole("view")); got != 1 {
		t.Fatalf("expected statement for view, got %d", got)
	}
	if got := len(statementsForRole("unknown")); got != 0 {
		t.Fatalf("expected no statements for unknown role, got %d", got)
	}
}
