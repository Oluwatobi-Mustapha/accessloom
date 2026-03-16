package aws

import (
	"context"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

func TestPolicyPermissionResolverExpandsTuples(t *testing.T) {
	normalizer := NewRoleNormalizer()
	bundle, err := normalizer.Normalize(context.Background(), []providers.RawAsset{loadRawRoleAssetFixture(t, "role_with_policies.json")})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}

	resolver := NewPolicyPermissionResolver()
	tuples, err := resolver.ResolvePermissions(context.Background(), bundle)
	if err != nil {
		t.Fatalf("resolve permissions failed: %v", err)
	}

	if len(tuples) != 3 {
		t.Fatalf("expected 3 permission tuples, got %d", len(tuples))
	}
	for _, tuple := range tuples {
		if tuple.Effect != "Allow" {
			t.Fatalf("expected Allow tuples, got %q", tuple.Effect)
		}
	}
}

func TestPolicyPermissionResolverRejectsMalformedStatements(t *testing.T) {
	resolver := NewPolicyPermissionResolver()
	bundle := providers.NormalizedBundle{
		Policies: []domain.Policy{{
			ID: "bad-policy",
			Normalized: map[string]any{
				policyTypeKey: policyTypePerm,
				identityIDKey: "aws:identity:arn:aws:iam::1:role/demo",
				statementsKey: "not-an-array",
			},
		}},
	}

	_, err := resolver.ResolvePermissions(context.Background(), bundle)
	if err == nil {
		t.Fatal("expected error")
	}
}
