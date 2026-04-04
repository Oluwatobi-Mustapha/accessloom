package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/gin-gonic/gin"
)

func TestLegacyScopeAllowsPermission(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	if legacyScopeAllowsPermission(c, rbacPermissionFindingsRead) {
		t.Fatal("expected deny when scope_set is absent")
	}

	c.Set("auth.scope_set", newScopeSet([]string{scopeRead}))
	if !legacyScopeAllowsPermission(c, rbacPermissionFindingsRead) {
		t.Fatal("expected read permission for read scope")
	}
	if legacyScopeAllowsPermission(c, rbacPermissionScansRun) {
		t.Fatal("expected write permission deny for read scope")
	}

	c.Set("auth.scope_set", newScopeSet([]string{scopeWrite}))
	if !legacyScopeAllowsPermission(c, rbacPermissionScansRun) {
		t.Fatal("expected write permission for write scope")
	}

	c.Set("auth.scope_set", newScopeSet([]string{scopeAdmin}))
	if !legacyScopeAllowsPermission(c, rbacPermissionRBACManage) {
		t.Fatal("expected admin permission for admin scope")
	}
	if legacyScopeAllowsPermission(c, "unknown.permission") {
		t.Fatal("expected deny for unknown permission")
	}
}

func TestRBACAuthorizerAllowFallbacks(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	a := &rbacAuthorizer{}
	allowed, err := a.allow(c, rbacPermissionFindingsRead)
	if err != nil {
		t.Fatalf("allow without auth context: %v", err)
	}
	if !allowed {
		t.Fatal("expected allow when auth middleware is disabled")
	}

	c.Set("auth.subject", "subject-1")
	c.Set("auth.scope_set", newScopeSet([]string{scopeRead}))
	allowed, err = a.allow(c, rbacPermissionFindingsRead)
	if err != nil {
		t.Fatalf("allow legacy fallback: %v", err)
	}
	if !allowed {
		t.Fatal("expected allow via legacy scope fallback")
	}

	delete(c.Keys, "auth.scope_set")
	allowed, err = a.allow(c, rbacPermissionFindingsRead)
	if err != nil {
		t.Fatalf("allow legacy deny path: %v", err)
	}
	if allowed {
		t.Fatal("expected deny without legacy scope set")
	}
}

func TestRBACAuthorizerEnsureBuiltinRolesAndAllow(t *testing.T) {
	store := db.NewMemoryStore()
	a := &rbacAuthorizer{store: store, now: func() time.Time { return time.Date(2026, 4, 4, 20, 0, 0, 0, time.UTC) }}
	ctx := defaultScopeContext()

	if err := a.ensureBuiltinRoles(ctx); err != nil {
		t.Fatalf("seed builtin roles: %v", err)
	}
	if err := a.ensureBuiltinRoles(ctx); err != nil {
		t.Fatalf("seed builtin roles idempotent: %v", err)
	}

	roles, err := store.ListRBACRoles(ctx)
	if err != nil {
		t.Fatalf("list seeded roles: %v", err)
	}
	if len(roles) < 4 {
		t.Fatalf("expected builtin roles to be seeded, got %d", len(roles))
	}

	var viewerRole db.RBACRole
	for _, role := range roles {
		if role.Name == "viewer" {
			viewerRole = role
			break
		}
	}
	if viewerRole.ID == "" {
		t.Fatal("expected viewer role in seeded set")
	}
	if _, err := store.UpsertRBACBinding(ctx, db.RBACBinding{
		SubjectType: db.RBACSubjectTypeOIDCSubject,
		SubjectID:   "alice",
		RoleID:      viewerRole.ID,
	}); err != nil {
		t.Fatalf("upsert viewer binding: %v", err)
	}

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request = req.WithContext(ctx)
	c.Set("auth.principal_type", db.RBACSubjectTypeOIDCSubject)
	c.Set("auth.principal_id", "alice")

	allowed, err := a.allow(c, rbacPermissionFindingsRead)
	if err != nil {
		t.Fatalf("allow read with viewer binding: %v", err)
	}
	if !allowed {
		t.Fatal("expected viewer binding to grant findings.read")
	}

	allowed, err = a.allow(c, rbacPermissionScansRun)
	if err != nil {
		t.Fatalf("allow run with viewer binding: %v", err)
	}
	if allowed {
		t.Fatal("expected viewer binding to deny scans.run")
	}
}

func TestRBACAuthorizerBootstrapAPIKeyBinding(t *testing.T) {
	store := db.NewMemoryStore()
	a := &rbacAuthorizer{store: store, now: time.Now}
	ctx := defaultScopeContext()
	if err := a.ensureBuiltinRoles(ctx); err != nil {
		t.Fatalf("seed builtin roles: %v", err)
	}

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request = req.WithContext(ctx)
	c.Set("auth.principal_id", "key-fingerprint")
	c.Set("auth.scope_set", newScopeSet([]string{scopeWrite}))

	if err := a.bootstrapAPIKeyBinding(c); err != nil {
		t.Fatalf("bootstrap api key binding: %v", err)
	}

	permissions, err := store.ListRBACPermissionsForSubject(ctx, db.RBACSubjectTypeAPIKey, "key-fingerprint", time.Now().UTC())
	if err != nil {
		t.Fatalf("list api key permissions: %v", err)
	}
	if len(permissions) == 0 {
		t.Fatal("expected permissions from bootstrap binding")
	}
}

func TestRBACAuthorizerBootstrapAPIKeyBindingNoopCases(t *testing.T) {
	store := db.NewMemoryStore()
	a := &rbacAuthorizer{store: store, now: time.Now}
	ctx := defaultScopeContext()
	if err := a.ensureBuiltinRoles(ctx); err != nil {
		t.Fatalf("seed builtin roles: %v", err)
	}

	cases := []struct {
		name string
		set  func(*gin.Context)
	}{
		{
			name: "missing principal id",
			set: func(c *gin.Context) {
				c.Set("auth.scope_set", newScopeSet([]string{scopeRead}))
			},
		},
		{
			name: "missing scope set",
			set: func(c *gin.Context) {
				c.Set("auth.principal_id", "api-key-fp")
			},
		},
		{
			name: "invalid scope set type",
			set: func(c *gin.Context) {
				c.Set("auth.principal_id", "api-key-fp")
				c.Set("auth.scope_set", "invalid")
			},
		},
		{
			name: "unmapped scope set",
			set: func(c *gin.Context) {
				c.Set("auth.principal_id", "api-key-fp")
				c.Set("auth.scope_set", newScopeSet([]string{"custom.scope"}))
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			c.Request = req.WithContext(ctx)
			tc.set(c)
			if err := a.bootstrapAPIKeyBinding(c); err != nil {
				t.Fatalf("bootstrap noop case should not error: %v", err)
			}
		})
	}
}

func TestRequireRBACPermissionMiddlewareResponses(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("empty permission bypass", func(t *testing.T) {
		r := gin.New()
		r.Use(requireRBACPermissionMiddleware(&rbacAuthorizer{}, "  "))
		r.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		if w.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", w.Code)
		}
	})

	t.Run("authorization error", func(t *testing.T) {
		a := &rbacAuthorizer{store: db.NewMemoryStore(), now: time.Now}
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Set("auth.principal_type", db.RBACSubjectTypeOIDCSubject)
			c.Set("auth.principal_id", "subject-1")
			c.Next()
		})
		r.Use(requireRBACPermissionMiddleware(a, rbacPermissionFindingsRead))
		r.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", w.Code)
		}
	})

	t.Run("forbidden", func(t *testing.T) {
		a := &rbacAuthorizer{store: db.NewMemoryStore(), now: time.Now}
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(defaultScopeContext())
			c.Set("auth.principal_type", db.RBACSubjectTypeOIDCSubject)
			c.Set("auth.principal_id", "subject-1")
			c.Next()
		})
		r.Use(requireRBACPermissionMiddleware(a, rbacPermissionFindingsRead))
		r.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})

	t.Run("allow", func(t *testing.T) {
		a := &rbacAuthorizer{store: db.NewMemoryStore(), now: time.Now}
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(defaultScopeContext())
			c.Set("auth.principal_type", db.RBACSubjectTypeAPIKey)
			c.Set("auth.principal_id", "api-key-fp")
			c.Set("auth.scope_set", newScopeSet([]string{scopeRead}))
			c.Next()
		})
		r.Use(requireRBACPermissionMiddleware(a, rbacPermissionFindingsRead))
		r.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		if w.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", w.Code)
		}
	})
}

func TestRBACAuthorizerNowUTC(t *testing.T) {
	var nilAuthorizer *rbacAuthorizer
	if nilAuthorizer.nowUTC().IsZero() {
		t.Fatal("expected non-zero time for nil authorizer")
	}

	a := &rbacAuthorizer{now: func() time.Time { return time.Date(2026, 4, 4, 23, 30, 0, 0, time.FixedZone("WAT", 3600)) }}
	if got := a.nowUTC(); got.Location() != time.UTC {
		t.Fatalf("expected UTC time, got %v", got.Location())
	}
}

func TestRBACAuthorizerEnsureBuiltinRolesRequiresScope(t *testing.T) {
	a := &rbacAuthorizer{store: db.NewMemoryStore(), now: time.Now}
	if err := a.ensureBuiltinRoles(context.Background()); err == nil {
		t.Fatal("expected scope-required error")
	}
}

func TestRouterAuthContextHelpers(t *testing.T) {
	if got := authContextString(nil, "auth.subject"); got != "" {
		t.Fatalf("expected empty string for nil context, got %q", got)
	}
	if got := triageActorFromContext(nil); got != "unknown" {
		t.Fatalf("expected unknown actor for nil context, got %q", got)
	}

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	if got := authContextString(c, "missing"); got != "" {
		t.Fatalf("expected empty string for missing key, got %q", got)
	}
	c.Set("auth.subject", 123)
	if got := authContextString(c, "auth.subject"); got != "" {
		t.Fatalf("expected empty string for non-string context value, got %q", got)
	}
	c.Set("auth.subject", "  alice  ")
	if got := authContextString(c, "auth.subject"); got != "alice" {
		t.Fatalf("expected trimmed auth subject, got %q", got)
	}
	if got := triageActorFromContext(c); got != "subject:alice" {
		t.Fatalf("expected subject actor, got %q", got)
	}

	c.Set("auth.subject", "   ")
	c.Set("auth.api_key", "key-1")
	expected := "api_key:" + fingerprintAPIKey("key-1")
	if got := triageActorFromContext(c); got != expected {
		t.Fatalf("expected api key actor %q, got %q", expected, got)
	}
}

func TestScopeSetFromOIDCToken(t *testing.T) {
	token := VerifiedToken{Scopes: []string{"identrail.read", "custom:writer"}}
	overrides := newScopeSet([]string{"custom:writer"})

	set := scopeSetFromOIDCToken(token, overrides)
	if !set.has(scopeRead) || !set.has(scopeWrite) {
		t.Fatalf("expected read and write from read scope + override, got %+v", set)
	}

	admin := scopeSetFromOIDCToken(VerifiedToken{Scopes: []string{"identrail.admin"}}, nil)
	if !admin.has(scopeAdmin) || !admin.has(scopeRead) || !admin.has(scopeWrite) {
		t.Fatalf("expected admin scope expansion, got %+v", admin)
	}
}
