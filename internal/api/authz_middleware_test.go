package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/Oluwatobi-Mustapha/identrail/internal/telemetry"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
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
	roles := policyRolesFromAuth(c, nil, nil)
	if len(roles) != 2 {
		t.Fatalf("expected read+write roles, got %+v", roles)
	}
}

func TestPolicyRolesFromAuthLegacyKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set("auth.api_key", "writer-key")
	roles := policyRolesFromAuth(c, []string{"writer-key"}, nil)
	if len(roles) != 2 {
		t.Fatalf("expected legacy writer to map to read+write roles, got %+v", roles)
	}
}

func TestRequireCentralPolicyMiddlewareWriteDeniedForReadRole(t *testing.T) {
	r := newPolicyTestRouter(newScopeSet([]string{scopeRead}), true, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestRequireCentralPolicyMiddlewareWriteAllowedForWriteRole(t *testing.T) {
	r := newPolicyTestRouter(newScopeSet([]string{scopeWrite}), true, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestRequireCentralPolicyMiddlewareBypassWhenAuthDisabled(t *testing.T) {
	r := newPolicyTestRouter(nil, false, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/scans", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 when auth is disabled, got %d", w.Code)
	}
}

func TestRoutePolicyRegistryCoversAllV1Routes(t *testing.T) {
	registry := newRoutePolicyRegistry()
	router := NewRouter(zap.NewNop(), telemetry.NewMetrics(), nil, RouterOptions{})
	for _, route := range router.Routes() {
		if !strings.HasPrefix(route.Path, "/v1/") {
			continue
		}
		if _, exists := registry.lookup(route.Method, route.Path); !exists {
			t.Fatalf("missing route policy for %s %s", route.Method, route.Path)
		}
	}
}

func TestRequireCentralPolicyMiddlewareABACTriageAllowsWhenTrustedAttributesMatch(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := policyTestScopeContext()
	if err := store.UpsertAuthzEntityAttributes(ctx, db.AuthzEntityAttributes{
		EntityKind: db.AuthzEntityKindSubject,
		EntityType: "subject",
		EntityID:   "principal-1",
		OwnerTeam:  "platform",
	}); err != nil {
		t.Fatalf("upsert subject attributes: %v", err)
	}
	if err := store.UpsertAuthzEntityAttributes(ctx, db.AuthzEntityAttributes{
		EntityKind:     db.AuthzEntityKindResource,
		EntityType:     "finding",
		EntityID:       "finding-1",
		OwnerTeam:      "platform",
		Environment:    db.AuthzAttributeEnvProd,
		RiskTier:       db.AuthzAttributeRiskTierHigh,
		Classification: db.AuthzAttributeClassificationConfidential,
	}); err != nil {
		t.Fatalf("upsert resource attributes: %v", err)
	}

	r := newPolicyTriageRouter(newScopeSet([]string{scopeWrite}), true, store)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/findings/finding-1/triage", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestRequireCentralPolicyMiddlewareABACTriageDeniesWhenOwnerTeamMismatch(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := policyTestScopeContext()
	if err := store.UpsertAuthzEntityAttributes(ctx, db.AuthzEntityAttributes{
		EntityKind: db.AuthzEntityKindSubject,
		EntityType: "subject",
		EntityID:   "principal-1",
		OwnerTeam:  "platform",
	}); err != nil {
		t.Fatalf("upsert subject attributes: %v", err)
	}
	if err := store.UpsertAuthzEntityAttributes(ctx, db.AuthzEntityAttributes{
		EntityKind:     db.AuthzEntityKindResource,
		EntityType:     "finding",
		EntityID:       "finding-1",
		OwnerTeam:      "security",
		Environment:    db.AuthzAttributeEnvProd,
		RiskTier:       db.AuthzAttributeRiskTierHigh,
		Classification: db.AuthzAttributeClassificationConfidential,
	}); err != nil {
		t.Fatalf("upsert resource attributes: %v", err)
	}

	r := newPolicyTriageRouter(newScopeSet([]string{scopeWrite}), true, store)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/findings/finding-1/triage", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestRequireCentralPolicyMiddlewareABACTriageAllowsWhenOwnerTeamMismatchAndReBACDirectGrant(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := policyTestScopeContext()
	if err := store.UpsertAuthzEntityAttributes(ctx, db.AuthzEntityAttributes{
		EntityKind: db.AuthzEntityKindSubject,
		EntityType: "subject",
		EntityID:   "principal-1",
		OwnerTeam:  "platform",
	}); err != nil {
		t.Fatalf("upsert subject attributes: %v", err)
	}
	if err := store.UpsertAuthzEntityAttributes(ctx, db.AuthzEntityAttributes{
		EntityKind:     db.AuthzEntityKindResource,
		EntityType:     "finding",
		EntityID:       "finding-1",
		OwnerTeam:      "security",
		Environment:    db.AuthzAttributeEnvProd,
		RiskTier:       db.AuthzAttributeRiskTierHigh,
		Classification: db.AuthzAttributeClassificationConfidential,
	}); err != nil {
		t.Fatalf("upsert resource attributes: %v", err)
	}
	if err := store.UpsertAuthzRelationship(ctx, db.AuthzRelationship{
		SubjectType: "subject",
		SubjectID:   "principal-1",
		Relation:    db.AuthzRelationshipDelegatedAdmin,
		ObjectType:  "finding",
		ObjectID:    "finding-1",
	}); err != nil {
		t.Fatalf("upsert delegated_admin relationship: %v", err)
	}

	r := newPolicyTriageRouter(newScopeSet([]string{scopeWrite}), true, store)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/findings/finding-1/triage", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestRequireCentralPolicyMiddlewareABACTriageAllowsWhenOwnerTeamMismatchAndReBACMemberOfGrant(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := policyTestScopeContext()
	if err := store.UpsertAuthzEntityAttributes(ctx, db.AuthzEntityAttributes{
		EntityKind: db.AuthzEntityKindSubject,
		EntityType: "subject",
		EntityID:   "principal-1",
		OwnerTeam:  "platform",
	}); err != nil {
		t.Fatalf("upsert subject attributes: %v", err)
	}
	if err := store.UpsertAuthzEntityAttributes(ctx, db.AuthzEntityAttributes{
		EntityKind:     db.AuthzEntityKindResource,
		EntityType:     "finding",
		EntityID:       "finding-1",
		OwnerTeam:      "security",
		Environment:    db.AuthzAttributeEnvProd,
		RiskTier:       db.AuthzAttributeRiskTierHigh,
		Classification: db.AuthzAttributeClassificationConfidential,
	}); err != nil {
		t.Fatalf("upsert resource attributes: %v", err)
	}
	if err := store.UpsertAuthzRelationship(ctx, db.AuthzRelationship{
		SubjectType: "subject",
		SubjectID:   "principal-1",
		Relation:    db.AuthzRelationshipMemberOf,
		ObjectType:  "team",
		ObjectID:    "platform-admins",
	}); err != nil {
		t.Fatalf("upsert member_of relationship: %v", err)
	}
	if err := store.UpsertAuthzRelationship(ctx, db.AuthzRelationship{
		SubjectType: "team",
		SubjectID:   "platform-admins",
		Relation:    db.AuthzRelationshipManages,
		ObjectType:  "finding",
		ObjectID:    "finding-1",
	}); err != nil {
		t.Fatalf("upsert manages relationship: %v", err)
	}

	r := newPolicyTriageRouter(newScopeSet([]string{scopeWrite}), true, store)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/findings/finding-1/triage", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestRequireCentralPolicyMiddlewareABACTriageAllowsWhenTrustedAttributesMissing(t *testing.T) {
	store := db.NewMemoryStore()
	if err := store.UpsertAuthzEntityAttributes(policyTestScopeContext(), db.AuthzEntityAttributes{
		EntityKind: db.AuthzEntityKindSubject,
		EntityType: "subject",
		EntityID:   "principal-1",
		OwnerTeam:  "platform",
	}); err != nil {
		t.Fatalf("upsert subject attributes: %v", err)
	}

	r := newPolicyTriageRouter(newScopeSet([]string{scopeWrite}), true, store)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/v1/findings/finding-1/triage", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestTrustedAttributesFromStoreNormalizesEnumCasing(t *testing.T) {
	store := authzOverrideStore{
		Store: db.NewMemoryStore(),
		records: map[string]db.AuthzEntityAttributes{
			"resource|finding|finding-1": {
				EntityKind:     db.AuthzEntityKindResource,
				EntityType:     "finding",
				EntityID:       "finding-1",
				OwnerTeam:      "Platform_Sec",
				Environment:    "Prod",
				RiskTier:       "High",
				Classification: "Confidential",
			},
		},
	}

	attributes, err := trustedAttributesFromStore(policyTestScopeContext(), store, db.AuthzEntityKindResource, "finding", "finding-1")
	if err != nil {
		t.Fatalf("trusted attributes from store: %v", err)
	}
	if got := attributes[policyAttributeOwnerTeam]; got != "platform_sec" {
		t.Fatalf("expected normalized owner_team, got %q", got)
	}
	if got := attributes[policyAttributeEnvironment]; got != "prod" {
		t.Fatalf("expected normalized env, got %q", got)
	}
	if got := attributes[policyAttributeRiskTier]; got != "high" {
		t.Fatalf("expected normalized risk_tier, got %q", got)
	}
	if got := attributes[policyAttributeClassification]; got != "confidential" {
		t.Fatalf("expected normalized classification, got %q", got)
	}
}

func newPolicyTestRouter(scopes scopeSet, setPrincipal bool, store db.Store) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(db.WithScope(c.Request.Context(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}))
		if scopes != nil {
			c.Set("auth.scope_set", scopes)
		}
		if setPrincipal {
			c.Set("auth.principal_type", "subject")
			c.Set("auth.principal_id", "principal-1")
		}
		c.Next()
	})
	r.Use(requireCentralPolicyMiddleware(newCentralPolicyEngine(store), newRoutePolicyRegistry(), nil, nil, store))
	r.POST("/v1/scans", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	return r
}

func newPolicyTriageRouter(scopes scopeSet, setPrincipal bool, store db.Store) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(db.WithScope(c.Request.Context(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"}))
		if scopes != nil {
			c.Set("auth.scope_set", scopes)
		}
		if setPrincipal {
			c.Set("auth.principal_type", "subject")
			c.Set("auth.principal_id", "principal-1")
		}
		c.Next()
	})
	r.Use(requireCentralPolicyMiddleware(newCentralPolicyEngine(store), newRoutePolicyRegistry(), nil, nil, store))
	r.PATCH("/v1/findings/:finding_id/triage", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})
	return r
}

func policyTestScopeContext() context.Context {
	return db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
}

type authzOverrideStore struct {
	db.Store
	records map[string]db.AuthzEntityAttributes
}

func (s authzOverrideStore) GetAuthzEntityAttributes(_ context.Context, entityKind string, entityType string, entityID string) (db.AuthzEntityAttributes, error) {
	key := strings.ToLower(strings.TrimSpace(entityKind)) + "|" + strings.ToLower(strings.TrimSpace(entityType)) + "|" + strings.TrimSpace(entityID)
	if record, exists := s.records[key]; exists {
		return record, nil
	}
	return db.AuthzEntityAttributes{}, db.ErrNotFound
}
