package db

import (
	"context"
	"strings"
)

const (
	// DefaultTenantID applies when no tenant is explicitly provided in context.
	DefaultTenantID = "default"
	// DefaultWorkspaceID applies when no workspace is explicitly provided in context.
	DefaultWorkspaceID = "default"
)

// Scope represents the active tenant/workspace boundary for a request.
type Scope struct {
	TenantID    string
	WorkspaceID string
}

type scopeContextKey struct{}

// Normalize returns a canonical, non-empty scope using secure defaults.
func (s Scope) Normalize() Scope {
	tenantID := strings.TrimSpace(s.TenantID)
	if tenantID == "" {
		tenantID = DefaultTenantID
	}
	workspaceID := strings.TrimSpace(s.WorkspaceID)
	if workspaceID == "" {
		workspaceID = DefaultWorkspaceID
	}
	return Scope{
		TenantID:    tenantID,
		WorkspaceID: workspaceID,
	}
}

// WithScope stores scope in context.
func WithScope(ctx context.Context, scope Scope) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, scopeContextKey{}, scope.Normalize())
}

// LookupScope returns scope from context when present.
func LookupScope(ctx context.Context) (Scope, bool) {
	if ctx == nil {
		return Scope{}, false
	}
	raw := ctx.Value(scopeContextKey{})
	scope, ok := raw.(Scope)
	if !ok {
		return Scope{}, false
	}
	return scope.Normalize(), true
}

// ScopeFromContext always returns a non-empty scope.
func ScopeFromContext(ctx context.Context) Scope {
	if scope, ok := LookupScope(ctx); ok {
		return scope
	}
	return Scope{}.Normalize()
}

// WithDefaultScope applies fallback scope only when context has no scope.
func WithDefaultScope(ctx context.Context, fallback Scope) context.Context {
	if _, ok := LookupScope(ctx); ok {
		return ctx
	}
	return WithScope(ctx, fallback)
}

// MatchScope returns true when record scope matches the active scope.
func MatchScope(scope Scope, tenantID string, workspaceID string) bool {
	normalized := scope.Normalize()
	return strings.TrimSpace(tenantID) == normalized.TenantID &&
		strings.TrimSpace(workspaceID) == normalized.WorkspaceID
}
