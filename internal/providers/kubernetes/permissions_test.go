package kubernetes

import (
	"context"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

func TestPermissionResolverExpandsTuples(t *testing.T) {
	normalizer := NewNormalizer()
	bundle, err := normalizer.Normalize(context.Background(), []providers.RawAsset{
		loadRawFixture(t, "k8s_service_account", "service_account_payments.json", "k8s:sa:apps:payments-api"),
		loadRawFixture(t, "k8s_role_binding", "role_binding_cluster_admin.json", "k8s:rb:cluster:payments-cluster-admin"),
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}

	tuples, err := NewPermissionResolver().ResolvePermissions(context.Background(), bundle)
	if err != nil {
		t.Fatalf("resolve permissions failed: %v", err)
	}
	if len(tuples) != 1 {
		t.Fatalf("expected 1 tuple, got %d", len(tuples))
	}
	tuple := tuples[0]
	if tuple.IdentityID != serviceAccountID("apps", "payments-api") {
		t.Fatalf("unexpected identity id %q", tuple.IdentityID)
	}
	if tuple.Action != "*" || tuple.Resource != "*" || tuple.Effect != "Allow" {
		t.Fatalf("unexpected tuple: %+v", tuple)
	}
}

func TestPermissionResolverRejectsMalformedStatements(t *testing.T) {
	bundle := providers.NormalizedBundle{
		Policies: []domain.Policy{
			{
				ID: "bad",
				Normalized: map[string]any{
					policyTypeKey: policyTypePerm,
					identityIDKey: "k8s:identity:sa:apps:bad",
					statementsKey: "oops",
				},
			},
		},
	}
	_, err := NewPermissionResolver().ResolvePermissions(context.Background(), bundle)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseStatements(t *testing.T) {
	_, err := parseStatements([]any{map[string]any{"effect": "Allow"}})
	if err != nil {
		t.Fatalf("expected parse success, got %v", err)
	}
	if _, err := parseStatements("bad"); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestParseStringList(t *testing.T) {
	if got := parseStringList([]string{"get", "list"}); len(got) != 2 {
		t.Fatalf("expected []string parse, got %+v", got)
	}
	if got := parseStringList([]any{"get", 4, "list"}); len(got) != 2 {
		t.Fatalf("expected []any parse with string filtering, got %+v", got)
	}
	if got := parseStringList("get"); len(got) != 1 || got[0] != "get" {
		t.Fatalf("expected string parse, got %+v", got)
	}
	if got := parseStringList(5); len(got) != 0 {
		t.Fatalf("expected empty parse for unsupported type, got %+v", got)
	}
}
