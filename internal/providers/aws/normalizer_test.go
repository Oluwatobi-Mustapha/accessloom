package aws

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

func TestRoleNormalizerNormalizeFromFixture(t *testing.T) {
	normalizer := NewRoleNormalizer()
	raw := []providers.RawAsset{loadRawRoleAssetFixture(t, "role_with_policies.json")}

	bundle, err := normalizer.Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}

	if got := len(bundle.Identities); got != 1 {
		t.Fatalf("expected 1 identity, got %d", got)
	}
	identity := bundle.Identities[0]
	if identity.OwnerHint != "payments" {
		t.Fatalf("expected owner hint payments, got %q", identity.OwnerHint)
	}
	if !strings.Contains(identity.ID, "arn:aws:iam::123456789012:role/payments-app") {
		t.Fatalf("unexpected identity id %q", identity.ID)
	}

	if got := len(bundle.Policies); got != 2 {
		t.Fatalf("expected 2 policies (permission + trust), got %d", got)
	}

	policyTypeCount := map[string]int{}
	for _, policy := range bundle.Policies {
		typeName, _ := policy.Normalized[policyTypeKey].(string)
		policyTypeCount[typeName]++
	}
	if policyTypeCount[policyTypePerm] != 1 {
		t.Fatalf("expected 1 permission policy, got %d", policyTypeCount[policyTypePerm])
	}
	if policyTypeCount[policyTypeTrust] != 1 {
		t.Fatalf("expected 1 trust policy, got %d", policyTypeCount[policyTypeTrust])
	}
}

func TestRoleNormalizerDecodesURLTrustPolicy(t *testing.T) {
	normalizer := NewRoleNormalizer()
	raw := []providers.RawAsset{loadRawRoleAssetFixture(t, "role_with_urlencoded_trust.json")}

	bundle, err := normalizer.Normalize(context.Background(), raw)
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if len(bundle.Policies) != 1 {
		t.Fatalf("expected 1 trust policy, got %d", len(bundle.Policies))
	}

	principals := parseStringList(bundle.Policies[0].Normalized[principalsKey])
	if len(principals) != 1 || principals[0] != "arn:aws:iam::123456789012:role/etl-runner" {
		t.Fatalf("unexpected principals: %+v", principals)
	}
}

func TestRoleNormalizerSkipsUnsupportedAndDeduplicates(t *testing.T) {
	normalizer := NewRoleNormalizer()
	asset := loadRawRoleAssetFixture(t, "role_with_policies.json")

	bundle, err := normalizer.Normalize(context.Background(), []providers.RawAsset{
		{Kind: "unknown", SourceID: "noop", Payload: []byte("{}")},
		asset,
		asset,
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if len(bundle.Identities) != 1 {
		t.Fatalf("expected deduplicated identity count 1, got %d", len(bundle.Identities))
	}
}

func TestRoleNormalizerInvalidPayload(t *testing.T) {
	normalizer := NewRoleNormalizer()
	_, err := normalizer.Normalize(context.Background(), []providers.RawAsset{{Kind: "iam_role", Payload: []byte("not-json")}})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "decode iam role") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRoleNormalizerInvalidPermissionPolicyDocument(t *testing.T) {
	role := IAMRole{
		ARN:                "arn:aws:iam::1:role/demo",
		Name:               "demo",
		PermissionPolicies: []IAMPermissionPolicy{{Name: "bad", Document: "{"}},
	}
	payload, _ := json.Marshal(role)

	normalizer := NewRoleNormalizer()
	_, err := normalizer.Normalize(context.Background(), []providers.RawAsset{{Kind: "iam_role", Payload: payload, SourceID: role.ARN}})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "normalize permission policies") {
		t.Fatalf("unexpected error: %v", err)
	}
}
