package api

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/gin-gonic/gin"
)

const (
	policyActionFindingsRead   = "findings.read"
	policyActionFindingsTriage = "findings.triage"
	policyActionGraphRead      = "graph.read"
	policyActionScansRead      = "scans.read"
	policyActionScansRun       = "scans.run"
	policyActionRepoScansRead  = "repo_scans.read"
	policyActionRepoScansRun   = "repo_scans.run"

	policyContextABACSubjectAttrsLoadedKey  = "abac.subject_attributes_loaded"
	policyContextABACResourceAttrsLoadedKey = "abac.resource_attributes_loaded"
)

type routePolicy struct {
	Action          string
	ResourceType    string
	ResourceIDParam string
}

type routePolicyRegistry map[string]routePolicy

func newRoutePolicyRegistry() routePolicyRegistry {
	return routePolicyRegistry{
		routePolicyKey(http.MethodGet, "/v1/findings"): {
			Action:       policyActionFindingsRead,
			ResourceType: "finding",
		},
		routePolicyKey(http.MethodGet, "/v1/findings/:finding_id"): {
			Action:          policyActionFindingsRead,
			ResourceType:    "finding",
			ResourceIDParam: "finding_id",
		},
		routePolicyKey(http.MethodGet, "/v1/findings/:finding_id/history"): {
			Action:          policyActionFindingsRead,
			ResourceType:    "finding_history",
			ResourceIDParam: "finding_id",
		},
		routePolicyKey(http.MethodGet, "/v1/findings/:finding_id/exports"): {
			Action:          policyActionFindingsRead,
			ResourceType:    "finding_export",
			ResourceIDParam: "finding_id",
		},
		routePolicyKey(http.MethodGet, "/v1/findings/trends"): {
			Action:       policyActionFindingsRead,
			ResourceType: "finding_trend",
		},
		routePolicyKey(http.MethodGet, "/v1/findings/summary"): {
			Action:       policyActionFindingsRead,
			ResourceType: "finding_summary",
		},
		routePolicyKey(http.MethodPatch, "/v1/findings/:finding_id/triage"): {
			Action:          policyActionFindingsTriage,
			ResourceType:    "finding",
			ResourceIDParam: "finding_id",
		},
		routePolicyKey(http.MethodGet, "/v1/identities"): {
			Action:       policyActionGraphRead,
			ResourceType: "identity",
		},
		routePolicyKey(http.MethodGet, "/v1/relationships"): {
			Action:       policyActionGraphRead,
			ResourceType: "relationship",
		},
		routePolicyKey(http.MethodGet, "/v1/ownership/signals"): {
			Action:       policyActionGraphRead,
			ResourceType: "ownership_signal",
		},
		routePolicyKey(http.MethodGet, "/v1/scans"): {
			Action:       policyActionScansRead,
			ResourceType: "scan",
		},
		routePolicyKey(http.MethodGet, "/v1/scans/:scan_id/diff"): {
			Action:          policyActionScansRead,
			ResourceType:    "scan_diff",
			ResourceIDParam: "scan_id",
		},
		routePolicyKey(http.MethodGet, "/v1/scans/:scan_id/events"): {
			Action:          policyActionScansRead,
			ResourceType:    "scan_event",
			ResourceIDParam: "scan_id",
		},
		routePolicyKey(http.MethodPost, "/v1/scans"): {
			Action:       policyActionScansRun,
			ResourceType: "scan",
		},
		routePolicyKey(http.MethodGet, "/v1/repo-scans"): {
			Action:       policyActionRepoScansRead,
			ResourceType: "repo_scan",
		},
		routePolicyKey(http.MethodGet, "/v1/repo-scans/:repo_scan_id"): {
			Action:          policyActionRepoScansRead,
			ResourceType:    "repo_scan",
			ResourceIDParam: "repo_scan_id",
		},
		routePolicyKey(http.MethodGet, "/v1/repo-findings"): {
			Action:       policyActionRepoScansRead,
			ResourceType: "repo_finding",
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
	readRoles := []string{scopeRead, scopeWrite, scopeAdmin}
	writeRoles := []string{scopeWrite, scopeAdmin}
	return map[string][]string{
		policyActionFindingsRead:   readRoles,
		policyActionFindingsTriage: writeRoles,
		policyActionGraphRead:      readRoles,
		policyActionScansRead:      readRoles,
		policyActionScansRun:       writeRoles,
		policyActionRepoScansRead:  readRoles,
		policyActionRepoScansRun:   writeRoles,
	}
}

func newCentralPolicyEngine() *PolicyEngine {
	return NewPolicyEngine(
		newTenantIsolationEvaluator(),
		newRBACRequirementEvaluator(defaultRouteActionRoleGrants()),
		newABACPolicyEvaluator(defaultRouteActionABACPolicies()),
		nil,
	)
}

func defaultRouteActionABACPolicies() map[string]abacActionPolicy {
	passThroughPolicy := abacActionPolicy{
		AnyOf: []abacClause{{}},
	}
	return map[string]abacActionPolicy{
		policyActionFindingsRead:  passThroughPolicy,
		policyActionGraphRead:     passThroughPolicy,
		policyActionScansRead:     passThroughPolicy,
		policyActionScansRun:      passThroughPolicy,
		policyActionRepoScansRead: passThroughPolicy,
		policyActionRepoScansRun:  passThroughPolicy,
		policyActionFindingsTriage: {
			AnyOf: []abacClause{
				{
					AllOf: []abacPredicate{
						{
							Source:   abacAttributeSourceContext,
							Key:      policyContextABACSubjectAttrsLoadedKey,
							Operator: abacOperatorEquals,
							Value:    "false",
						},
					},
				},
				{
					AllOf: []abacPredicate{
						{
							Source:   abacAttributeSourceContext,
							Key:      policyContextABACResourceAttrsLoadedKey,
							Operator: abacOperatorEquals,
							Value:    "false",
						},
					},
				},
				{
					AllOf: []abacPredicate{
						{
							Source:        abacAttributeSourceSubject,
							Key:           policyAttributeOwnerTeam,
							Operator:      abacOperatorEqualsAttribute,
							CompareSource: abacAttributeSourceResource,
							CompareKey:    policyAttributeOwnerTeam,
						},
						{
							Source:   abacAttributeSourceResource,
							Key:      policyAttributeEnvironment,
							Operator: abacOperatorOneOf,
							Values: []string{
								db.AuthzAttributeEnvProd,
								db.AuthzAttributeEnvStaging,
								db.AuthzAttributeEnvDev,
								db.AuthzAttributeEnvTest,
								db.AuthzAttributeEnvSandbox,
							},
						},
						{
							Source:   abacAttributeSourceResource,
							Key:      policyAttributeRiskTier,
							Operator: abacOperatorOneOf,
							Values: []string{
								db.AuthzAttributeRiskTierLow,
								db.AuthzAttributeRiskTierMedium,
								db.AuthzAttributeRiskTierHigh,
								db.AuthzAttributeRiskTierCritical,
							},
						},
						{
							Source:   abacAttributeSourceResource,
							Key:      policyAttributeClassification,
							Operator: abacOperatorOneOf,
							Values: []string{
								db.AuthzAttributeClassificationPublic,
								db.AuthzAttributeClassificationInternal,
								db.AuthzAttributeClassificationConfidential,
								db.AuthzAttributeClassificationRestricted,
							},
						},
					},
				},
			},
		},
	}
}

func requireCentralPolicyMiddleware(engine *PolicyEngine, registry routePolicyRegistry, writeKeys []string, scopedKeys map[string][]string, store db.Store) gin.HandlerFunc {
	normalizedWriteKeys := normalizeKeyList(writeKeys)
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

		input, err := buildPolicyInputFromGinContext(c, policy, normalizedWriteKeys, scopedKeys, store)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "authorization failed"})
			return
		}

		decision, err := engine.Decide(c.Request.Context(), input)
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

func buildPolicyInputFromGinContext(c *gin.Context, policy routePolicy, writeKeys []string, scopedKeys map[string][]string, store db.Store) (PolicyInput, error) {
	scope := db.ScopeFromContext(c.Request.Context())
	resourceID := ""
	if strings.TrimSpace(policy.ResourceIDParam) != "" {
		resourceID = strings.TrimSpace(c.Param(policy.ResourceIDParam))
	}
	subjectType := firstNonEmpty(authContextString(c, "auth.principal_type"), inferPrincipalType(c))
	subjectID := firstNonEmpty(authContextString(c, "auth.principal_id"), inferPrincipalID(c))
	input := PolicyInput{
		Subject: PolicySubject{
			Type:        subjectType,
			ID:          subjectID,
			TenantID:    firstNonEmpty(authContextString(c, "auth.tenant_id"), strings.TrimSpace(scope.TenantID)),
			WorkspaceID: firstNonEmpty(authContextString(c, "auth.workspace_id"), strings.TrimSpace(scope.WorkspaceID)),
			Roles:       policyRolesFromAuth(c, writeKeys, scopedKeys),
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
			Now:           time.Now().UTC(),
			Attributes: map[string]string{
				policyContextTenantIDKey:                strings.TrimSpace(scope.TenantID),
				policyContextWorkspaceIDKey:             strings.TrimSpace(scope.WorkspaceID),
				policyContextABACSubjectAttrsLoadedKey:  "false",
				policyContextABACResourceAttrsLoadedKey: "false",
			},
		},
	}

	if err := loadTrustedPolicyAttributes(c.Request.Context(), store, &input); err != nil {
		return PolicyInput{}, err
	}
	return input, nil
}

func firstNonEmpty(primary string, fallback string) string {
	if strings.TrimSpace(primary) != "" {
		return strings.TrimSpace(primary)
	}
	return strings.TrimSpace(fallback)
}

func inferPrincipalType(c *gin.Context) string {
	if c == nil {
		return ""
	}
	if authContextString(c, "auth.subject") != "" {
		return "subject"
	}
	if authContextString(c, "auth.api_key") != "" {
		return "api_key"
	}
	return ""
}

func inferPrincipalID(c *gin.Context) string {
	if c == nil {
		return ""
	}
	if subject := authContextString(c, "auth.subject"); subject != "" {
		return subject
	}
	if apiKey := authContextString(c, "auth.api_key"); apiKey != "" {
		return apiKey
	}
	return ""
}

func hasAuthContext(c *gin.Context) bool {
	if c == nil {
		return false
	}
	if _, exists := c.Get("auth.scope_set"); exists {
		return true
	}
	if authContextString(c, "auth.api_key") != "" {
		return true
	}
	if authContextString(c, "auth.subject") != "" {
		return true
	}
	return false
}

func normalizeKeyList(keys []string) []string {
	normalized := make([]string, 0, len(keys))
	for _, key := range keys {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

func loadTrustedPolicyAttributes(ctx context.Context, store db.Store, input *PolicyInput) error {
	if store == nil || input == nil {
		return nil
	}

	subjectAttrs, err := trustedAttributesFromStore(ctx, store, db.AuthzEntityKindSubject, input.Subject.Type, input.Subject.ID)
	if err != nil {
		return err
	}
	resourceAttrs, err := trustedAttributesFromStore(ctx, store, db.AuthzEntityKindResource, input.Resource.Type, input.Resource.ID)
	if err != nil {
		return err
	}
	if len(subjectAttrs) > 0 {
		input.Subject.Attributes = subjectAttrs
		input.Context.Attributes[policyContextABACSubjectAttrsLoadedKey] = "true"
	}
	if len(resourceAttrs) > 0 {
		input.Resource.Attributes = resourceAttrs
		input.Context.Attributes[policyContextABACResourceAttrsLoadedKey] = "true"
	}
	return nil
}

func trustedAttributesFromStore(ctx context.Context, store db.Store, entityKind string, entityType string, entityID string) (map[string]string, error) {
	if store == nil {
		return nil, nil
	}
	normalizedType := strings.ToLower(strings.TrimSpace(entityType))
	normalizedID := strings.TrimSpace(entityID)
	if normalizedType == "" || normalizedID == "" {
		return nil, nil
	}

	record, err := store.GetAuthzEntityAttributes(ctx, entityKind, normalizedType, normalizedID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	normalizedRecord, err := db.NormalizeAuthzEntityAttributesForWrite(db.AuthzEntityAttributes{
		EntityKind:     entityKind,
		EntityType:     normalizedType,
		EntityID:       normalizedID,
		OwnerTeam:      record.OwnerTeam,
		Environment:    record.Environment,
		RiskTier:       record.RiskTier,
		Classification: record.Classification,
		UpdatedAt:      record.UpdatedAt,
	})
	if err != nil {
		return nil, err
	}

	attributes := map[string]string{}
	if value := strings.TrimSpace(normalizedRecord.OwnerTeam); value != "" {
		attributes[policyAttributeOwnerTeam] = value
	}
	if value := strings.TrimSpace(normalizedRecord.Environment); value != "" {
		attributes[policyAttributeEnvironment] = value
	}
	if value := strings.TrimSpace(normalizedRecord.RiskTier); value != "" {
		attributes[policyAttributeRiskTier] = value
	}
	if value := strings.TrimSpace(normalizedRecord.Classification); value != "" {
		attributes[policyAttributeClassification] = value
	}
	return attributes, nil
}

func policyRolesFromAuth(c *gin.Context, writeKeys []string, scopedKeys map[string][]string) []string {
	if c == nil {
		return nil
	}
	if scopeSetValue, exists := c.Get("auth.scope_set"); exists {
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

	legacyKey := authContextString(c, "auth.api_key")
	if legacyKey == "" {
		return nil
	}
	// In scoped-key mode, the auth middleware should always set scope_set for valid keys.
	if len(scopedKeys) > 0 {
		return nil
	}
	roles := []string{scopeRead}
	if keyInList(writeKeys, legacyKey) {
		roles = append(roles, scopeWrite)
	}
	return roles
}
