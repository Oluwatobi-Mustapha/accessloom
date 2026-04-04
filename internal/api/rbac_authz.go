package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/gin-gonic/gin"
)

const (
	rbacPermissionFindingsRead   = "findings.read"
	rbacPermissionFindingsTriage = "findings.triage"
	rbacPermissionGraphRead      = "graph.read"
	rbacPermissionScansRead      = "scans.read"
	rbacPermissionScansRun       = "scans.run"
	rbacPermissionRepoScansRead  = "repo_scans.read"
	rbacPermissionRepoScansRun   = "repo_scans.run"
	rbacPermissionRBACManage     = "rbac.manage"
)

var builtinRBACRoles = []db.RBACRole{
	{
		Name:        "viewer",
		Description: "Read-only access to findings, graph, and scan results",
		IsBuiltIn:   true,
		Permissions: []string{
			rbacPermissionFindingsRead,
			rbacPermissionGraphRead,
			rbacPermissionScansRead,
			rbacPermissionRepoScansRead,
		},
	},
	{
		Name:        "analyst",
		Description: "Viewer access plus finding triage",
		IsBuiltIn:   true,
		Permissions: []string{
			rbacPermissionFindingsRead,
			rbacPermissionFindingsTriage,
			rbacPermissionGraphRead,
			rbacPermissionScansRead,
			rbacPermissionRepoScansRead,
		},
	},
	{
		Name:        "operator",
		Description: "Analyst access plus scan execution",
		IsBuiltIn:   true,
		Permissions: []string{
			rbacPermissionFindingsRead,
			rbacPermissionFindingsTriage,
			rbacPermissionGraphRead,
			rbacPermissionScansRead,
			rbacPermissionScansRun,
			rbacPermissionRepoScansRead,
			rbacPermissionRepoScansRun,
		},
	},
	{
		Name:        "admin",
		Description: "Full workspace administrative access",
		IsBuiltIn:   true,
		Permissions: []string{
			rbacPermissionFindingsRead,
			rbacPermissionFindingsTriage,
			rbacPermissionGraphRead,
			rbacPermissionScansRead,
			rbacPermissionScansRun,
			rbacPermissionRepoScansRead,
			rbacPermissionRepoScansRun,
			rbacPermissionRBACManage,
		},
	},
}

type rbacAuthorizer struct {
	store   db.Store
	now     func() time.Time
	seeded  sync.Map
	seedMux sync.Mutex
}

func newRBACAuthorizer(svc *Service) *rbacAuthorizer {
	if svc == nil || svc.Store == nil {
		return &rbacAuthorizer{now: time.Now}
	}
	return &rbacAuthorizer{
		store: svc.Store,
		now:   time.Now,
	}
}

func requireRBACPermissionMiddleware(authorizer *rbacAuthorizer, permission string) gin.HandlerFunc {
	required := strings.ToLower(strings.TrimSpace(permission))
	return func(c *gin.Context) {
		if strings.TrimSpace(required) == "" {
			c.Next()
			return
		}
		allowed, err := authorizer.allow(c, required)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "authorization failed"})
			return
		}
		if !allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Next()
	}
}

func (a *rbacAuthorizer) allow(c *gin.Context, permission string) (bool, error) {
	if c == nil {
		return false, nil
	}

	principalType := authContextString(c, "auth.principal_type")
	principalID := authContextString(c, "auth.principal_id")

	if principalType == "" || principalID == "" {
		// Authentication middleware is disabled, keep local/test behavior unchanged.
		if authContextString(c, "auth.subject") == "" && authContextString(c, "auth.api_key") == "" {
			return true, nil
		}
		return legacyScopeAllowsPermission(c, permission), nil
	}

	if a == nil || a.store == nil {
		return legacyScopeAllowsPermission(c, permission), nil
	}

	if err := a.ensureBuiltinRoles(c.Request.Context()); err != nil {
		return false, err
	}

	if principalType == db.RBACSubjectTypeAPIKey {
		if err := a.bootstrapAPIKeyBinding(c); err != nil {
			return false, err
		}
	}

	permissions, err := a.store.ListRBACPermissionsForSubject(c.Request.Context(), principalType, principalID, a.nowUTC())
	if err != nil {
		return false, err
	}
	for _, granted := range permissions {
		normalized := strings.ToLower(strings.TrimSpace(granted))
		if normalized == permission || normalized == "*" {
			return true, nil
		}
	}
	return false, nil
}

func (a *rbacAuthorizer) ensureBuiltinRoles(ctx context.Context) error {
	if a == nil || a.store == nil {
		return nil
	}
	scope, err := db.RequireScope(ctx)
	if err != nil {
		return err
	}
	scopeKey := scope.TenantID + "|" + scope.WorkspaceID
	if _, loaded := a.seeded.Load(scopeKey); loaded {
		return nil
	}

	a.seedMux.Lock()
	defer a.seedMux.Unlock()
	if _, loaded := a.seeded.Load(scopeKey); loaded {
		return nil
	}
	for _, role := range builtinRBACRoles {
		if _, err := a.store.UpsertRBACRole(ctx, role); err != nil {
			return err
		}
	}
	a.seeded.Store(scopeKey, struct{}{})
	return nil
}

func (a *rbacAuthorizer) bootstrapAPIKeyBinding(c *gin.Context) error {
	if a == nil || a.store == nil || c == nil {
		return nil
	}
	principalID := authContextString(c, "auth.principal_id")
	if principalID == "" {
		return nil
	}
	scopeSetValue, exists := c.Get("auth.scope_set")
	if !exists {
		return nil
	}
	scopes, ok := scopeSetValue.(scopeSet)
	if !ok {
		return nil
	}

	roleName := "viewer"
	switch {
	case scopes.has(scopeAdmin):
		roleName = "admin"
	case scopes.has(scopeWrite):
		roleName = "operator"
	case scopes.has(scopeRead):
		roleName = "viewer"
	default:
		return nil
	}

	var selected db.RBACRole
	for _, role := range builtinRBACRoles {
		if role.Name == roleName {
			selected = role
			break
		}
	}
	if selected.Name == "" {
		return fmt.Errorf("missing built-in role %q", roleName)
	}
	upserted, err := a.store.UpsertRBACRole(c.Request.Context(), selected)
	if err != nil {
		return err
	}
	_, err = a.store.UpsertRBACBinding(c.Request.Context(), db.RBACBinding{
		SubjectType: db.RBACSubjectTypeAPIKey,
		SubjectID:   principalID,
		RoleID:      upserted.ID,
	})
	return err
}

func (a *rbacAuthorizer) nowUTC() time.Time {
	if a == nil || a.now == nil {
		return time.Now().UTC()
	}
	return a.now().UTC()
}

func legacyScopeAllowsPermission(c *gin.Context, permission string) bool {
	if c == nil {
		return false
	}
	scopeSetValue, exists := c.Get("auth.scope_set")
	if !exists {
		return false
	}
	scopes, ok := scopeSetValue.(scopeSet)
	if !ok {
		return false
	}
	switch permission {
	case rbacPermissionFindingsRead, rbacPermissionGraphRead, rbacPermissionScansRead, rbacPermissionRepoScansRead:
		return scopes.has(scopeRead)
	case rbacPermissionFindingsTriage, rbacPermissionScansRun, rbacPermissionRepoScansRun:
		return scopes.has(scopeWrite)
	case rbacPermissionRBACManage:
		return scopes.has(scopeAdmin)
	default:
		return false
	}
}
