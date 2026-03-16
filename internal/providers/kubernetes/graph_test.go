package kubernetes

import (
	"context"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

func TestRelationshipResolverBuildsExpectedEdges(t *testing.T) {
	normalizer := NewNormalizer()
	bundle, err := normalizer.Normalize(context.Background(), []providers.RawAsset{
		loadRawFixture(t, "k8s_service_account", "service_account_payments.json", "k8s:sa:apps:payments-api"),
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

	fixedNow := time.Date(2026, 3, 16, 12, 0, 0, 0, time.UTC)
	resolver := NewRelationshipResolver()
	resolver.now = func() time.Time { return fixedNow }
	relationships, err := resolver.ResolveRelationships(context.Background(), bundle, perms)
	if err != nil {
		t.Fatalf("resolve relationships failed: %v", err)
	}

	var boundTo, attachedPolicy, canAccess int
	for _, relationship := range relationships {
		if !relationship.DiscoveredAt.Equal(fixedNow) {
			t.Fatalf("unexpected discovered_at %v", relationship.DiscoveredAt)
		}
		switch relationship.Type {
		case domain.RelationshipBoundTo:
			boundTo++
		case domain.RelationshipAttachedPolicy:
			attachedPolicy++
		case domain.RelationshipCanAccess:
			canAccess++
		}
	}
	if boundTo != 1 || attachedPolicy != 1 || canAccess != 1 {
		t.Fatalf("unexpected relationship counts bound_to=%d attached_policy=%d can_access=%d", boundTo, attachedPolicy, canAccess)
	}
}
