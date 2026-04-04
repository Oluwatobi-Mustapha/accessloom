package db

import (
	"context"
	"testing"
)

func TestScopeFromContextDefaults(t *testing.T) {
	scope := ScopeFromContext(context.Background())
	if scope.TenantID != DefaultTenantID || scope.WorkspaceID != DefaultWorkspaceID {
		t.Fatalf("unexpected default scope: %+v", scope)
	}
}

func TestWithDefaultScopeDoesNotOverrideExistingScope(t *testing.T) {
	ctx := WithScope(context.Background(), Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	ctx = WithDefaultScope(ctx, Scope{TenantID: "tenant-b", WorkspaceID: "workspace-b"})
	scope := ScopeFromContext(ctx)
	if scope.TenantID != "tenant-a" || scope.WorkspaceID != "workspace-a" {
		t.Fatalf("expected existing scope preserved, got %+v", scope)
	}
}

func TestMatchScope(t *testing.T) {
	scope := Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}
	if !MatchScope(scope, "tenant-a", "workspace-a") {
		t.Fatal("expected scope match")
	}
	if MatchScope(scope, "tenant-b", "workspace-a") {
		t.Fatal("expected scope mismatch for tenant")
	}
	if MatchScope(scope, "tenant-a", "workspace-b") {
		t.Fatal("expected scope mismatch for workspace")
	}
}
