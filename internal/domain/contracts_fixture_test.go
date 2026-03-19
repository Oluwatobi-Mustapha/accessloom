package domain_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	awsprovider "github.com/Oluwatobi-Mustapha/identrail/internal/providers/aws"
	k8sprovider "github.com/Oluwatobi-Mustapha/identrail/internal/providers/kubernetes"
)

func TestAWSFixtureGraphContract(t *testing.T) {
	ctx := context.Background()
	collector := awsprovider.NewFixtureCollector([]string{
		fixturePath("aws", "role_with_policies.json"),
		fixturePath("aws", "role_with_urlencoded_trust.json"),
	})
	rawAssets, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("collect aws fixtures: %v", err)
	}

	bundle, err := awsprovider.NewRoleNormalizer().Normalize(ctx, rawAssets)
	if err != nil {
		t.Fatalf("normalize aws fixtures: %v", err)
	}
	perms, err := awsprovider.NewPolicyPermissionResolver().ResolvePermissions(ctx, bundle)
	if err != nil {
		t.Fatalf("resolve aws permissions: %v", err)
	}
	relationships, err := awsprovider.NewRelationshipBuilder().ResolveRelationships(ctx, bundle, perms)
	if err != nil {
		t.Fatalf("resolve aws relationships: %v", err)
	}

	if len(bundle.Identities) == 0 {
		t.Fatal("expected identities from aws fixtures")
	}
	if len(relationships) == 0 {
		t.Fatal("expected relationships from aws fixtures")
	}

	for _, identity := range bundle.Identities {
		if !identity.Validate() {
			t.Fatalf("invalid normalized identity: %+v", identity)
		}
	}
	for _, relationship := range relationships {
		if !domain.IsSupportedRelationshipType(relationship.Type) {
			t.Fatalf("unsupported relationship type in aws pipeline: %s", relationship.Type)
		}
	}
}

func TestKubernetesFixtureGraphContract(t *testing.T) {
	ctx := context.Background()
	collector := k8sprovider.NewFixtureCollector([]string{
		fixturePath("kubernetes", "service_account_payments.json"),
		fixturePath("kubernetes", "cluster_role_cluster_admin.json"),
		fixturePath("kubernetes", "role_binding_cluster_admin.json"),
		fixturePath("kubernetes", "pod_payments.json"),
	})
	rawAssets, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("collect k8s fixtures: %v", err)
	}

	bundle, err := k8sprovider.NewNormalizer().Normalize(ctx, rawAssets)
	if err != nil {
		t.Fatalf("normalize k8s fixtures: %v", err)
	}
	perms, err := k8sprovider.NewPermissionResolver().ResolvePermissions(ctx, bundle)
	if err != nil {
		t.Fatalf("resolve k8s permissions: %v", err)
	}
	relationships, err := k8sprovider.NewRelationshipResolver().ResolveRelationships(ctx, bundle, perms)
	if err != nil {
		t.Fatalf("resolve k8s relationships: %v", err)
	}

	if len(bundle.Identities) == 0 {
		t.Fatal("expected identities from k8s fixtures")
	}
	if len(relationships) == 0 {
		t.Fatal("expected relationships from k8s fixtures")
	}

	for _, identity := range bundle.Identities {
		if !identity.Validate() {
			t.Fatalf("invalid normalized identity: %+v", identity)
		}
	}
	for _, relationship := range relationships {
		if !domain.IsSupportedRelationshipType(relationship.Type) {
			t.Fatalf("unsupported relationship type in k8s pipeline: %s", relationship.Type)
		}
	}
}

func fixturePath(group string, name string) string {
	return filepath.Join("..", "..", "testdata", group, name)
}
