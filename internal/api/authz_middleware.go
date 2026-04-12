package api

import (
	"context"
	"errors"
	"hash/fnv"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/Oluwatobi-Mustapha/identrail/internal/telemetry"
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
	policyActionAuthzSimulate  = "authz.policies.simulate"
	policyActionAuthzRollback  = "authz.policies.rollback"

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
	compiled, err := compileBuiltInRouteAuthorizationPolicyBundle()
	if err != nil {
		return routePolicyRegistry{}
	}
	return compiled.RouteRegistry
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
		policyActionAuthzSimulate:  {scopeAdmin},
		policyActionAuthzRollback:  {scopeAdmin},
	}
}

func newCentralPolicyEngine(store db.Store) *PolicyEngine {
	compiled, err := compileBuiltInRouteAuthorizationPolicyBundle()
	if err != nil {
		compiled = emptyCompiledRouteAuthorizationPolicy()
	}
	return newCentralPolicyEngineFromCompiled(store, compiled)
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
		policyActionAuthzSimulate: passThroughPolicy,
		policyActionAuthzRollback: passThroughPolicy,
		policyActionFindingsTriage: {
			OnNoMatch: PolicyOutcomeNoOpinion,
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

func defaultRouteActionReBACPolicies() map[string]rebacActionPolicy {
	memberDelegationConditions := []abacPredicate{
		{
			Source:   abacAttributeSourceResource,
			Key:      policyAttributeEnvironment,
			Operator: abacOperatorOneOf,
			Values: []string{
				db.AuthzAttributeEnvProd,
				db.AuthzAttributeEnvStaging,
			},
		},
		{
			Source:   abacAttributeSourceResource,
			Key:      policyAttributeRiskTier,
			Operator: abacOperatorOneOf,
			Values: []string{
				db.AuthzAttributeRiskTierHigh,
				db.AuthzAttributeRiskTierCritical,
			},
		},
		{
			Source:   abacAttributeSourceResource,
			Key:      policyAttributeClassification,
			Operator: abacOperatorOneOf,
			Values: []string{
				db.AuthzAttributeClassificationConfidential,
				db.AuthzAttributeClassificationRestricted,
			},
		},
	}
	return map[string]rebacActionPolicy{
		policyActionFindingsTriage: {
			AnyOf: []rebacRelationPath{
				{Relations: []string{db.AuthzRelationshipOwns}},
				{Relations: []string{db.AuthzRelationshipManages}},
				{Relations: []string{db.AuthzRelationshipDelegatedAdmin}},
				{
					Relations: []string{db.AuthzRelationshipMemberOf, db.AuthzRelationshipOwns},
					AllOf:     memberDelegationConditions,
				},
				{
					Relations: []string{db.AuthzRelationshipMemberOf, db.AuthzRelationshipManages},
					AllOf:     memberDelegationConditions,
				},
				{
					Relations: []string{db.AuthzRelationshipMemberOf, db.AuthzRelationshipDelegatedAdmin},
					AllOf:     memberDelegationConditions,
				},
			},
		},
	}
}

func requireCentralPolicyMiddleware(resolver centralPolicyRuntimeResolver, writeKeys []string, scopedKeys map[string][]string, store db.Store, metrics *telemetry.Metrics) gin.HandlerFunc {
	normalizedWriteKeys := normalizeKeyList(writeKeys)
	if resolver == nil {
		resolver = newCentralPolicyRuntimeResolver(store)
	}
	var shadowEvalCount uint64
	var shadowDivergenceCount uint64
	return func(c *gin.Context) {
		fullPath := strings.TrimSpace(c.FullPath())
		if fullPath == "" {
			c.Next()
			return
		}

		if !hasAuthContext(c) {
			// Keep local/dev behavior unchanged when authentication is disabled.
			c.Next()
			return
		}

		runtimePolicy, err := resolver.Resolve(c.Request.Context())
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "authorization failed"})
			return
		}
		policy, exists := runtimePolicy.Registry.lookup(c.Request.Method, fullPath)
		if !exists {
			c.Next()
			return
		}

		input, err := buildPolicyInputFromGinContext(c, policy, normalizedWriteKeys, scopedKeys, store)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "authorization failed"})
			return
		}

		targeted := shouldTargetRolloutRequest(runtimePolicy.Rollout, input)
		enforceCandidate := runtimePolicy.Rollout.Mode == db.AuthzPolicyRolloutModeEnforce &&
			targeted &&
			runtimePolicy.CandidateEngine != nil &&
			rolloutVersionValidated(runtimePolicy.Rollout, runtimePolicy.CandidateVersion)

		decisionEngine := runtimePolicy.Engine
		decisionSource := runtimePolicy.Source
		decisionVersion := runtimePolicy.Version
		if enforceCandidate {
			decisionEngine = runtimePolicy.CandidateEngine
			decisionSource = runtimePolicy.CandidateSource
			decisionVersion = runtimePolicy.CandidateVersion
		}

		decision, err := decisionEngine.Decide(c.Request.Context(), input)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "authorization failed"})
			return
		}
		recordPolicyDecisionMetric(metrics, runtimePolicy.PolicySetID, decisionVersion, decisionSource, runtimePolicy.RolloutMode, decision.Allowed)

		if runtimePolicy.Rollout.Mode == db.AuthzPolicyRolloutModeShadow &&
			targeted &&
			runtimePolicy.CandidateEngine != nil &&
			rolloutVersionValidated(runtimePolicy.Rollout, runtimePolicy.CandidateVersion) {
			if metrics != nil && metrics.AuthzPolicyShadowEvaluationsTotal != nil {
				metrics.AuthzPolicyShadowEvaluationsTotal.Inc()
			}
			totalEvaluations := atomic.AddUint64(&shadowEvalCount, 1)
			candidateDecision, err := runtimePolicy.CandidateEngine.Decide(c.Request.Context(), input)
			if err != nil {
				if metrics != nil && metrics.AuthzPolicyShadowEvaluationErrorsTotal != nil {
					metrics.AuthzPolicyShadowEvaluationErrorsTotal.Inc()
				}
			} else if policyDecisionsDiverge(decision, candidateDecision) {
				if metrics != nil && metrics.AuthzPolicyShadowDivergencesTotal != nil {
					metrics.AuthzPolicyShadowDivergencesTotal.Inc()
				}
				atomic.AddUint64(&shadowDivergenceCount, 1)
			}
			if metrics != nil && metrics.AuthzPolicyShadowDivergenceRate != nil && totalEvaluations > 0 {
				divergences := atomic.LoadUint64(&shadowDivergenceCount)
				metrics.AuthzPolicyShadowDivergenceRate.Set(float64(divergences) / float64(totalEvaluations))
			}
		}

		setAuthzDecisionContext(c, runtimePolicy.PolicySetID, decisionVersion, decisionSource, runtimePolicy.RolloutMode, decision, input)

		if !decision.Allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}

		c.Next()
	}
}

func shouldTargetRolloutRequest(rollout db.AuthzPolicyRollout, input PolicyInput) bool {
	canary := rollout.CanaryPercentage
	if canary <= 0 {
		return false
	}
	if canary > 100 {
		canary = 100
	}
	tenantID := firstNonEmpty(
		input.Resource.TenantID,
		firstNonEmpty(input.Subject.TenantID, strings.TrimSpace(input.Context.Attributes[policyContextTenantIDKey])),
	)
	workspaceID := firstNonEmpty(
		input.Resource.WorkspaceID,
		firstNonEmpty(input.Subject.WorkspaceID, strings.TrimSpace(input.Context.Attributes[policyContextWorkspaceIDKey])),
	)

	if len(rollout.TenantAllowlist) > 0 && !containsStringExact(rollout.TenantAllowlist, tenantID) {
		return false
	}
	if len(rollout.WorkspaceAllowlist) > 0 && !containsStringExact(rollout.WorkspaceAllowlist, workspaceID) {
		return false
	}
	if canary >= 100 {
		return true
	}
	bucket := deterministicCanaryBucket(strings.Join([]string{
		strings.TrimSpace(rollout.PolicySetID),
		tenantID,
		workspaceID,
		strings.TrimSpace(input.Subject.Type),
		strings.TrimSpace(input.Subject.ID),
		strings.TrimSpace(input.Action),
		strings.TrimSpace(input.Resource.Type),
		strings.TrimSpace(input.Resource.ID),
	}, "|"))
	return bucket < canary
}

func deterministicCanaryBucket(seed string) int {
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(strings.TrimSpace(seed)))
	return int(hasher.Sum64() % 100)
}

func containsStringExact(values []string, target string) bool {
	for _, candidate := range values {
		if strings.TrimSpace(candidate) == strings.TrimSpace(target) {
			return true
		}
	}
	return false
}

func rolloutVersionValidated(rollout db.AuthzPolicyRollout, version int) bool {
	if version <= 0 {
		return false
	}
	for _, validated := range rollout.ValidatedVersions {
		if validated == version {
			return true
		}
	}
	return false
}

func policyDecisionsDiverge(current PolicyDecision, candidate PolicyDecision) bool {
	return current.Allowed != candidate.Allowed || current.Stage != candidate.Stage
}

func recordPolicyDecisionMetric(metrics *telemetry.Metrics, policySetID string, version int, source string, rolloutMode string, allowed bool) {
	if metrics == nil || metrics.AuthzPolicyDecisionsByVersionTotal == nil {
		return
	}
	set := strings.TrimSpace(policySetID)
	if set == "" {
		set = defaultCentralPolicySetID
	}
	versionLabel := "built_in"
	if version > 0 {
		versionLabel = strconv.Itoa(version)
	}
	sourceLabel := strings.TrimSpace(source)
	if sourceLabel == "" {
		sourceLabel = "unknown"
	}
	modeLabel := strings.TrimSpace(rolloutMode)
	if modeLabel == "" {
		modeLabel = db.AuthzPolicyRolloutModeDisabled
	}
	allowedLabel := "false"
	if allowed {
		allowedLabel = "true"
	}
	metrics.AuthzPolicyDecisionsByVersionTotal.WithLabelValues(set, versionLabel, sourceLabel, modeLabel, allowedLabel).Inc()
}

func setAuthzDecisionContext(c *gin.Context, policySetID string, policyVersion int, policySource string, rolloutMode string, decision PolicyDecision, input PolicyInput) {
	if c == nil {
		return
	}

	normalizedPolicySetID := strings.TrimSpace(policySetID)
	if normalizedPolicySetID == "" {
		normalizedPolicySetID = defaultCentralPolicySetID
	}
	normalizedPolicySource := strings.TrimSpace(policySource)
	if normalizedPolicySource == "" {
		normalizedPolicySource = "unknown"
	}
	normalizedRolloutMode := strings.TrimSpace(rolloutMode)
	if normalizedRolloutMode == "" {
		normalizedRolloutMode = db.AuthzPolicyRolloutModeDisabled
	}
	tenantID := firstNonEmpty(
		input.Resource.TenantID,
		firstNonEmpty(input.Subject.TenantID, strings.TrimSpace(input.Context.Attributes[policyContextTenantIDKey])),
	)
	workspaceID := firstNonEmpty(
		input.Resource.WorkspaceID,
		firstNonEmpty(input.Subject.WorkspaceID, strings.TrimSpace(input.Context.Attributes[policyContextWorkspaceIDKey])),
	)

	auditDecision := AuditAuthzDecision{
		PolicySetID:  normalizedPolicySetID,
		PolicySource: normalizedPolicySource,
		RolloutMode:  normalizedRolloutMode,
		Allowed:      decision.Allowed,
		Stage:        strings.TrimSpace(string(decision.Stage)),
		Reason:       strings.TrimSpace(decision.Reason),
		Input: AuditAuthzInputSummary{
			SubjectType:    strings.TrimSpace(input.Subject.Type),
			SubjectIDHash:  fingerprintAuditIdentifier(input.Subject.ID),
			Action:         strings.TrimSpace(input.Action),
			ResourceType:   strings.TrimSpace(input.Resource.Type),
			ResourceIDHash: fingerprintAuditIdentifier(input.Resource.ID),
			TenantID:       tenantID,
			WorkspaceID:    workspaceID,
		},
	}
	if policyVersion > 0 {
		version := policyVersion
		auditDecision.PolicyVersion = &version
	}

	c.Set("authz.stage", auditDecision.Stage)
	c.Set("authz.policy_source", auditDecision.PolicySource)
	c.Set("authz.policy_set_id", auditDecision.PolicySetID)
	c.Set("authz.rollout_mode", auditDecision.RolloutMode)
	if auditDecision.PolicyVersion != nil {
		c.Set("authz.policy_version", *auditDecision.PolicyVersion)
	}
	c.Set("authz.audit_decision", auditDecision)
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
