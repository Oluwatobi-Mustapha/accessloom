package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/gin-gonic/gin"
)

func TestRoutePolicyRegistryLookup(t *testing.T) {
	registry := newRoutePolicyRegistry()
	policy, exists := registry.lookup(http.MethodPost, "/v1/scans")
	if !exists {
		t.Fatal("expected policy for POST /v1/scans")
	}
	if policy.Action != policyActionScansRun {
		t.Fatalf("expected scans.run action, got %q", policy.Action)
	}
}

func TestPolicyRolesFromScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set("auth.scope_set", newScopeSet([]string{scopeWrite}))
	roles := policyRolesFromScope(c)
	if len(roles) != 2 {
		t.Fatalf("expected read+write roles, got %+v", roles)
	}
}

func TestRequireCentralPolicyMiddlewareWriteDeniedForReadRole(t *testing.T) {
	r := newPolicyTestRouter(newScopeSet([]string{scopeRead}), true)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestRequireCentralPolicyMiddlewareWriteAllowedForWriteRole(t *testing.T) {
	r := newPolicyTestRouter(newScopeSet([]string{scopeWrite}), true)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestRequireCentralPolicyMiddlewareBypassWhenAuthDisabled(t *testing.T) {
	r := newPolicyTestRouter(nil, false)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 when auth is disabled, got %d", w.Code)
	}
}

func newPolicyTestRouter(scopes scopeSet, setPrincipal bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(db.WithScope(c.Request.Context(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}))
		if scopes != nil {
			c.Set("auth.scope_set", scopes)
		}
		if setPrincipal {
			c.Set("auth.principal_id", "principal-1")
		}
		c.Next()
	})
	r.Use(requireCentralPolicyMiddleware(newCentralPolicyEngine(), newRoutePolicyRegistry()))
	r.POST("/v1/scans", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	return r
}
