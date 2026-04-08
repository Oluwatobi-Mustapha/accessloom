package api

import (
	"net/http"
	"sort"
	"strings"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/gin-gonic/gin"
)

const (
	policyActionFindingsTriage = "findings.triage"
	policyActionScansRun       = "scans.run"
	policyActionRepoScansRun   = "repo_scans.run"
)

type routePolicy struct {
	Action          string
	ResourceType    string
	ResourceIDParam string
}

type routePolicyRegistry map[string]routePolicy

func newRoutePolicyRegistry() routePolicyRegistry {
	return routePolicyRegistry{
		routePolicyKey(http.MethodPatch, "/v1/findings/:finding_id/triage"): {
			Action:          policyActionFindingsTriage,
			ResourceType:    "finding",
			ResourceIDParam: "finding_id",
		},
		routePolicyKey(http.MethodPost, "/v1/scans"): {
			Action:       policyActionScansRun,
			ResourceType: "scan",
		},
		routePolicyKey(http.MethodPost, "/v1/repo-scans"): {
			Action:       policyActionRepoScansRun,
			ResourceType: "repo_scan",
		},
	}
}

func (r routePolicyRegistry) lookup(method string, fullPath string) (routePolicy, bool) {
	policy, exists := r[routePolicyKey(method, fullPath)]
	return policy, exists
}

func routePolicyKey(method string, fullPath string) string {
	return strings.ToUpper(strings.TrimSpace(method)) + " " + strings.TrimSpace(fullPath)
}

func defaultRouteActionRoleGrants() map[string][]string {
	return map[string][]string{
		policyActionFindingsTriage: {scopeWrite, scopeAdmin},
		policyActionScansRun:       {scopeWrite, scopeAdmin},
		policyActionRepoScansRun:   {scopeWrite, scopeAdmin},
	}
}

func newCentralPolicyEngine() *PolicyEngine {
	return NewPolicyEngine(
		newTenantIsolationEvaluator(),
		newRBACPolicyEvaluator(defaultRouteActionRoleGrants()),
		nil,
		nil,
	)
}

func requireCentralPolicyMiddleware(engine *PolicyEngine, registry routePolicyRegistry) gin.HandlerFunc {
	return func(c *gin.Context) {
		fullPath := strings.TrimSpace(c.FullPath())
		if fullPath == "" {
			c.Next()
			return
		}
		policy, exists := registry.lookup(c.Request.Method, fullPath)
		if !exists {
			c.Next()
			return
		}

		if !hasAuthContext(c) {
			// Keep local/dev behavior unchanged when authentication is disabled.
			c.Next()
			return
		}

		decision, err := engine.Decide(c.Request.Context(), buildPolicyInputFromGinContext(c, policy))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "authorization failed"})
			return
		}
		if !decision.Allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}

		c.Set("authz.stage", string(decision.Stage))
		c.Next()
	}
}

func buildPolicyInputFromGinContext(c *gin.Context, policy routePolicy) PolicyInput {
	scope := db.ScopeFromContext(c.Request.Context())
	resourceID := ""
	if strings.TrimSpace(policy.ResourceIDParam) != "" {
		resourceID = strings.TrimSpace(c.Param(policy.ResourceIDParam))
	}
	return PolicyInput{
		Subject: PolicySubject{
			Type:        authContextString(c, "auth.principal_type"),
			ID:          authContextString(c, "auth.principal_id"),
			TenantID:    firstNonEmpty(authContextString(c, "auth.tenant_id"), strings.TrimSpace(scope.TenantID)),
			WorkspaceID: firstNonEmpty(authContextString(c, "auth.workspace_id"), strings.TrimSpace(scope.WorkspaceID)),
			Roles:       policyRolesFromScope(c),
		},
		Action: strings.ToLower(strings.TrimSpace(policy.Action)),
		Resource: PolicyResource{
			Type:        strings.TrimSpace(policy.ResourceType),
			ID:          resourceID,
			TenantID:    strings.TrimSpace(scope.TenantID),
			WorkspaceID: strings.TrimSpace(scope.WorkspaceID),
		},
		Context: PolicyContext{
			RequestPath:   strings.TrimSpace(c.FullPath()),
			RequestMethod: strings.ToUpper(strings.TrimSpace(c.Request.Method)),
			Attributes: map[string]string{
				policyContextTenantIDKey:    strings.TrimSpace(scope.TenantID),
				policyContextWorkspaceIDKey: strings.TrimSpace(scope.WorkspaceID),
			},
		},
	}
}

func firstNonEmpty(primary string, fallback string) string {
	if strings.TrimSpace(primary) != "" {
		return strings.TrimSpace(primary)
	}
	return strings.TrimSpace(fallback)
}

func hasAuthContext(c *gin.Context) bool {
	if c == nil {
		return false
	}
	_, exists := c.Get("auth.scope_set")
	return exists
}

func policyRolesFromScope(c *gin.Context) []string {
	scopeSetValue, exists := c.Get("auth.scope_set")
	if !exists {
		return nil
	}
	scopes, ok := scopeSetValue.(scopeSet)
	if !ok {
		return nil
	}
	roles := map[string]struct{}{}
	if scopes.has(scopeAdmin) {
		roles[scopeAdmin] = struct{}{}
	}
	if scopes.has(scopeWrite) {
		roles[scopeWrite] = struct{}{}
	}
	if scopes.has(scopeRead) {
		roles[scopeRead] = struct{}{}
	}
	result := make([]string, 0, len(roles))
	for role := range roles {
		result = append(result, role)
	}
	sort.Strings(result)
	return result
}
