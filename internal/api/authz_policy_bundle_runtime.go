package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
)

const (
	routeAuthorizationPolicyBundleSchemaV1 = "identrail.authz.route_policy_bundle.v1"
	defaultCentralPolicySetID              = "central_authorization"
)

var errInvalidAuthzPolicyVersionBundle = errors.New("invalid authz policy version bundle")

type routePolicyDefinition struct {
	Method          string `json:"method"`
	Path            string `json:"path"`
	Action          string `json:"action"`
	ResourceType    string `json:"resource_type"`
	ResourceIDParam string `json:"resource_id_param,omitempty"`
}

type routeAuthorizationPolicyBundle struct {
	SchemaVersion  string                       `json:"schema_version"`
	RoutePolicies  []routePolicyDefinition      `json:"route_policies"`
	RBACActionRole map[string][]string          `json:"rbac_action_roles"`
	ABACPolicies   map[string]abacActionPolicy  `json:"abac_policies"`
	ReBACPolicies  map[string]rebacActionPolicy `json:"rebac_policies"`
}

type compiledRouteAuthorizationPolicy struct {
	RouteRegistry  routePolicyRegistry
	RBACActionRole map[string][]string
	ABACPolicies   map[string]abacActionPolicy
	ReBACPolicies  map[string]rebacActionPolicy
}

type resolvedCentralPolicyRuntime struct {
	Engine           *PolicyEngine
	Registry         routePolicyRegistry
	Source           string
	PolicySetID      string
	Version          int
	RolloutMode      string
	Rollout          db.AuthzPolicyRollout
	CandidateEngine  *PolicyEngine
	CandidateSource  string
	CandidateVersion int
}

type centralPolicyRuntimeResolver interface {
	Resolve(ctx context.Context) (resolvedCentralPolicyRuntime, error)
}

type storeBackedCentralPolicyRuntimeResolver struct {
	store      db.Store
	policySet  string
	fallback   compiledRouteAuthorizationPolicy
	initErr    error
	cacheByKey sync.Map
}

func newCentralPolicyRuntimeResolver(store db.Store) centralPolicyRuntimeResolver {
	return newCentralPolicyRuntimeResolverWithPolicySet(store, defaultCentralPolicySetID)
}

func newCentralPolicyRuntimeResolverWithPolicySet(store db.Store, policySetID string) centralPolicyRuntimeResolver {
	compiled, err := compileBuiltInRouteAuthorizationPolicyBundle()
	policySet := strings.TrimSpace(policySetID)
	if policySet == "" {
		policySet = defaultCentralPolicySetID
	}
	resolver := &storeBackedCentralPolicyRuntimeResolver{
		store:     store,
		policySet: policySet,
		fallback:  compiled,
	}
	if err != nil {
		resolver.fallback = emptyCompiledRouteAuthorizationPolicy()
		resolver.initErr = fmt.Errorf("compile built-in policy bundle: %w", err)
	}
	return resolver
}

func compileBuiltInRouteAuthorizationPolicyBundle() (compiledRouteAuthorizationPolicy, error) {
	return compileRouteAuthorizationPolicyBundle(defaultBuiltInRouteAuthorizationPolicyBundle())
}

func emptyCompiledRouteAuthorizationPolicy() compiledRouteAuthorizationPolicy {
	return compiledRouteAuthorizationPolicy{
		RouteRegistry:  routePolicyRegistry{},
		RBACActionRole: map[string][]string{},
		ABACPolicies:   map[string]abacActionPolicy{},
		ReBACPolicies:  map[string]rebacActionPolicy{},
	}
}

func (r *storeBackedCentralPolicyRuntimeResolver) Resolve(ctx context.Context) (resolvedCentralPolicyRuntime, error) {
	if r == nil {
		compiled, err := compileBuiltInRouteAuthorizationPolicyBundle()
		if err != nil {
			return resolvedCentralPolicyRuntime{}, fmt.Errorf("compile built-in policy bundle: %w", err)
		}
		return resolvedCentralPolicyRuntime{
			Engine:      newCentralPolicyEngineFromCompiled(nil, compiled),
			Registry:    compiled.RouteRegistry,
			Source:      "built_in_default",
			PolicySetID: defaultCentralPolicySetID,
			RolloutMode: db.AuthzPolicyRolloutModeDisabled,
			Rollout: db.AuthzPolicyRollout{
				PolicySetID:       defaultCentralPolicySetID,
				Mode:              db.AuthzPolicyRolloutModeDisabled,
				CanaryPercentage:  100,
				ValidatedVersions: nil,
			},
		}, nil
	}
	if r.initErr != nil {
		return resolvedCentralPolicyRuntime{}, r.initErr
	}
	fallback := r.fallbackRuntime()
	if r.store == nil {
		return fallback, nil
	}

	rollout, err := r.store.GetAuthzPolicyRollout(ctx, r.policySet)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return fallback, nil
		}
		return resolvedCentralPolicyRuntime{}, fmt.Errorf("resolve policy rollout: %w", err)
	}
	fallback.Rollout = normalizeRuntimeRollout(rollout, r.policySet)
	fallback.RolloutMode = fallback.Rollout.Mode

	resolved := fallback
	if fallback.Rollout.ActiveVersion != nil && *fallback.Rollout.ActiveVersion > 0 {
		version, err := r.store.GetAuthzPolicyVersion(ctx, r.policySet, *fallback.Rollout.ActiveVersion)
		if err != nil {
			if !errors.Is(err, db.ErrNotFound) {
				return resolvedCentralPolicyRuntime{}, fmt.Errorf("resolve active policy version: %w", err)
			}
		} else {
			compiled, err := r.compiledVersion(version)
			if err == nil {
				resolved.Engine = newCentralPolicyEngineFromCompiled(r.store, compiled)
				resolved.Registry = compiled.RouteRegistry
				resolved.Source = "persisted_active_version"
				resolved.Version = version.Version
			}
		}
	}

	if fallback.Rollout.CandidateVersion != nil && *fallback.Rollout.CandidateVersion > 0 {
		version, err := r.store.GetAuthzPolicyVersion(ctx, r.policySet, *fallback.Rollout.CandidateVersion)
		if err != nil {
			if !errors.Is(err, db.ErrNotFound) {
				return resolvedCentralPolicyRuntime{}, fmt.Errorf("resolve candidate policy version: %w", err)
			}
		} else {
			compiled, err := r.compiledVersion(version)
			if err == nil {
				resolved.CandidateEngine = newCentralPolicyEngineFromCompiled(r.store, compiled)
				resolved.CandidateSource = "persisted_candidate_version"
				resolved.CandidateVersion = version.Version
			}
		}
	}
	return resolved, nil
}

func (r *storeBackedCentralPolicyRuntimeResolver) fallbackRuntime() resolvedCentralPolicyRuntime {
	return resolvedCentralPolicyRuntime{
		Engine:      newCentralPolicyEngineFromCompiled(r.store, r.fallback),
		Registry:    r.fallback.RouteRegistry,
		Source:      "built_in_default",
		PolicySetID: r.policySet,
		RolloutMode: db.AuthzPolicyRolloutModeDisabled,
		Rollout: db.AuthzPolicyRollout{
			PolicySetID:      r.policySet,
			Mode:             db.AuthzPolicyRolloutModeDisabled,
			CanaryPercentage: 100,
		},
	}
}

func normalizeRuntimeRollout(rollout db.AuthzPolicyRollout, policySetID string) db.AuthzPolicyRollout {
	normalized := rollout
	normalized.PolicySetID = strings.ToLower(strings.TrimSpace(policySetID))
	if normalized.PolicySetID == "" {
		normalized.PolicySetID = defaultCentralPolicySetID
	}
	normalized.Mode = strings.ToLower(strings.TrimSpace(rollout.Mode))
	if normalized.Mode == "" {
		normalized.Mode = db.AuthzPolicyRolloutModeDisabled
	}
	if _, ok := map[string]struct{}{
		db.AuthzPolicyRolloutModeDisabled: {},
		db.AuthzPolicyRolloutModeShadow:   {},
		db.AuthzPolicyRolloutModeEnforce:  {},
	}[normalized.Mode]; !ok {
		normalized.Mode = db.AuthzPolicyRolloutModeDisabled
	}
	normalized.TenantAllowlist = normalizeRuntimeAllowlist(rollout.TenantAllowlist)
	normalized.WorkspaceAllowlist = normalizeRuntimeAllowlist(rollout.WorkspaceAllowlist)
	normalized.ValidatedVersions = normalizeRuntimeValidatedVersions(rollout.ValidatedVersions)
	normalized.CanaryPercentage = rollout.CanaryPercentage
	if normalized.CanaryPercentage <= 0 {
		normalized.CanaryPercentage = 100
	}
	if normalized.CanaryPercentage > 100 {
		normalized.CanaryPercentage = 100
	}
	return normalized
}

func normalizeRuntimeAllowlist(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		item := strings.TrimSpace(value)
		if item == "" {
			continue
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		normalized = append(normalized, item)
	}
	sort.Strings(normalized)
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func normalizeRuntimeValidatedVersions(values []int) []int {
	if len(values) == 0 {
		return nil
	}
	seen := map[int]struct{}{}
	normalized := make([]int, 0, len(values))
	for _, value := range values {
		if value <= 0 {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Ints(normalized)
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func (r *storeBackedCentralPolicyRuntimeResolver) compiledVersion(version db.AuthzPolicyVersion) (compiledRouteAuthorizationPolicy, error) {
	cacheKey := strings.ToLower(strings.TrimSpace(version.PolicySetID)) + "|" + strconv.Itoa(version.Version) + "|" + strings.ToLower(strings.TrimSpace(version.Checksum))
	if cacheKey != "||" {
		if cached, exists := r.cacheByKey.Load(cacheKey); exists {
			compiled, ok := cached.(compiledRouteAuthorizationPolicy)
			if ok {
				return compiled, nil
			}
		}
	}
	compiled, err := compileRouteAuthorizationPolicyBundleJSON(version.Bundle)
	if err != nil {
		return compiledRouteAuthorizationPolicy{}, fmt.Errorf("compile policy version %d: %w", version.Version, err)
	}
	if cacheKey != "||" {
		r.cacheByKey.Store(cacheKey, compiled)
	}
	return compiled, nil
}

func newCentralPolicyEngineFromCompiled(store db.Store, compiled compiledRouteAuthorizationPolicy) *PolicyEngine {
	return NewPolicyEngine(
		newTenantIsolationEvaluator(),
		newRBACRequirementEvaluator(compiled.RBACActionRole),
		newABACPolicyEvaluator(compiled.ABACPolicies),
		newReBACPolicyEvaluator(store, compiled.ReBACPolicies),
	)
}

func compileRouteAuthorizationPolicyBundleJSON(raw string) (compiledRouteAuthorizationPolicy, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return compiledRouteAuthorizationPolicy{}, fmt.Errorf("policy bundle is empty")
	}
	var bundle routeAuthorizationPolicyBundle
	if err := json.Unmarshal([]byte(trimmed), &bundle); err != nil {
		return compiledRouteAuthorizationPolicy{}, fmt.Errorf("decode policy bundle json: %w", err)
	}
	return compileRouteAuthorizationPolicyBundle(bundle)
}

func compileRouteAuthorizationPolicyBundle(bundle routeAuthorizationPolicyBundle) (compiledRouteAuthorizationPolicy, error) {
	if strings.TrimSpace(bundle.SchemaVersion) != routeAuthorizationPolicyBundleSchemaV1 {
		return compiledRouteAuthorizationPolicy{}, fmt.Errorf("unsupported policy bundle schema version %q", bundle.SchemaVersion)
	}

	registry, actions, err := compileRoutePolicies(bundle.RoutePolicies)
	if err != nil {
		return compiledRouteAuthorizationPolicy{}, err
	}
	rbac, err := compileRBACRoleGrants(bundle.RBACActionRole, actions)
	if err != nil {
		return compiledRouteAuthorizationPolicy{}, err
	}
	abac, err := compileABACPolicies(bundle.ABACPolicies, actions)
	if err != nil {
		return compiledRouteAuthorizationPolicy{}, err
	}
	rebac, err := compileReBACPolicies(bundle.ReBACPolicies, actions)
	if err != nil {
		return compiledRouteAuthorizationPolicy{}, err
	}

	return compiledRouteAuthorizationPolicy{
		RouteRegistry:  registry,
		RBACActionRole: rbac,
		ABACPolicies:   abac,
		ReBACPolicies:  rebac,
	}, nil
}

func compileRoutePolicies(definitions []routePolicyDefinition) (routePolicyRegistry, map[string]struct{}, error) {
	if len(definitions) == 0 {
		return nil, nil, fmt.Errorf("at least one route policy is required")
	}
	registry := routePolicyRegistry{}
	actions := map[string]struct{}{}
	for _, definition := range definitions {
		normalized, err := normalizeRoutePolicyDefinition(definition)
		if err != nil {
			return nil, nil, err
		}
		key := routePolicyKey(normalized.Method, normalized.Path)
		if _, exists := registry[key]; exists {
			return nil, nil, fmt.Errorf("duplicate route policy for %s %s", normalized.Method, normalized.Path)
		}
		registry[key] = routePolicy{
			Action:          normalized.Action,
			ResourceType:    normalized.ResourceType,
			ResourceIDParam: normalized.ResourceIDParam,
		}
		actions[normalized.Action] = struct{}{}
	}
	return registry, actions, nil
}

func normalizeRoutePolicyDefinition(definition routePolicyDefinition) (routePolicyDefinition, error) {
	method := strings.ToUpper(strings.TrimSpace(definition.Method))
	if method == "" {
		return routePolicyDefinition{}, fmt.Errorf("route policy method is required")
	}
	if _, ok := validHTTPMethods()[method]; !ok {
		return routePolicyDefinition{}, fmt.Errorf("unsupported route policy method %q", method)
	}
	path := strings.TrimSpace(definition.Path)
	if path == "" || !strings.HasPrefix(path, "/") {
		return routePolicyDefinition{}, fmt.Errorf("route policy path must be absolute")
	}
	if !strings.HasPrefix(path, "/v1/") {
		return routePolicyDefinition{}, fmt.Errorf("route policy path must target /v1 routes")
	}
	action := strings.ToLower(strings.TrimSpace(definition.Action))
	if action == "" {
		return routePolicyDefinition{}, fmt.Errorf("route policy action is required")
	}
	resourceType := strings.ToLower(strings.TrimSpace(definition.ResourceType))
	if resourceType == "" {
		return routePolicyDefinition{}, fmt.Errorf("route policy resource_type is required")
	}
	resourceIDParam := strings.TrimSpace(definition.ResourceIDParam)
	if resourceIDParam != "" {
		if !strings.Contains(path, ":"+resourceIDParam) {
			return routePolicyDefinition{}, fmt.Errorf("route policy resource_id_param %q is not present in path %q", resourceIDParam, path)
		}
	}
	return routePolicyDefinition{
		Method:          method,
		Path:            path,
		Action:          action,
		ResourceType:    resourceType,
		ResourceIDParam: resourceIDParam,
	}, nil
}

func compileRBACRoleGrants(grants map[string][]string, routeActions map[string]struct{}) (map[string][]string, error) {
	if len(grants) == 0 {
		return nil, fmt.Errorf("rbac_action_roles must not be empty")
	}
	normalized := map[string][]string{}
	for action, roles := range grants {
		normalizedAction := strings.ToLower(strings.TrimSpace(action))
		if normalizedAction == "" {
			return nil, fmt.Errorf("rbac action key is required")
		}
		if _, exists := routeActions[normalizedAction]; !exists {
			return nil, fmt.Errorf("rbac action %q is not referenced by any route policy", normalizedAction)
		}
		roleSet := map[string]struct{}{}
		for _, role := range roles {
			normalizedRole := strings.ToLower(strings.TrimSpace(role))
			if normalizedRole == "" {
				continue
			}
			roleSet[normalizedRole] = struct{}{}
		}
		if len(roleSet) == 0 {
			return nil, fmt.Errorf("rbac action %q must include at least one role", normalizedAction)
		}
		normalizedRoles := make([]string, 0, len(roleSet))
		for role := range roleSet {
			normalizedRoles = append(normalizedRoles, role)
		}
		sort.Strings(normalizedRoles)
		normalized[normalizedAction] = normalizedRoles
	}
	for action := range routeActions {
		if _, exists := normalized[action]; !exists {
			return nil, fmt.Errorf("rbac action %q is required by route policy but missing", action)
		}
	}
	return normalized, nil
}

func compileABACPolicies(policies map[string]abacActionPolicy, routeActions map[string]struct{}) (map[string]abacActionPolicy, error) {
	if len(policies) == 0 {
		return nil, fmt.Errorf("abac_policies must not be empty")
	}
	for action, policy := range policies {
		normalizedAction := strings.ToLower(strings.TrimSpace(action))
		if normalizedAction == "" {
			return nil, fmt.Errorf("abac policy action key is required")
		}
		if _, exists := routeActions[normalizedAction]; !exists {
			return nil, fmt.Errorf("abac policy action %q is not referenced by any route policy", normalizedAction)
		}
		if err := validateABACActionPolicy(policy, "abac_policies."+normalizedAction); err != nil {
			return nil, err
		}
	}
	normalized := normalizeABACPolicies(policies)
	for action := range routeActions {
		if _, exists := normalized[action]; !exists {
			return nil, fmt.Errorf("abac policy for action %q is required", action)
		}
	}
	return normalized, nil
}

func compileReBACPolicies(policies map[string]rebacActionPolicy, routeActions map[string]struct{}) (map[string]rebacActionPolicy, error) {
	if len(policies) == 0 {
		return map[string]rebacActionPolicy{}, nil
	}
	for action, policy := range policies {
		normalizedAction := strings.ToLower(strings.TrimSpace(action))
		if normalizedAction == "" {
			return nil, fmt.Errorf("rebac policy action key is required")
		}
		if _, exists := routeActions[normalizedAction]; !exists {
			return nil, fmt.Errorf("rebac policy action %q is not referenced by any route policy", normalizedAction)
		}
		if err := validateReBACActionPolicy(policy, "rebac_policies."+normalizedAction); err != nil {
			return nil, err
		}
	}
	return normalizeReBACPolicies(policies), nil
}

func validateABACActionPolicy(policy abacActionPolicy, path string) error {
	for clauseIndex, clause := range policy.AnyOf {
		for predicateIndex, predicate := range clause.AllOf {
			if err := validateABACPredicate(predicate); err != nil {
				return fmt.Errorf("%s.any_of[%d].all_of[%d]: %w", path, clauseIndex, predicateIndex, err)
			}
		}
	}
	normalizedOnNoMatch := strings.ToLower(strings.TrimSpace(string(policy.OnNoMatch)))
	if normalizedOnNoMatch != "" {
		switch PolicyOutcome(normalizedOnNoMatch) {
		case PolicyOutcomeNoOpinion, PolicyOutcomeAllow, PolicyOutcomeDeny:
		default:
			return fmt.Errorf("%s.on_no_match: invalid outcome %q", path, policy.OnNoMatch)
		}
	}
	return nil
}

func validateABACPredicate(predicate abacPredicate) error {
	source := strings.ToLower(strings.TrimSpace(string(predicate.Source)))
	switch abacAttributeSource(source) {
	case abacAttributeSourceSubject, abacAttributeSourceResource, abacAttributeSourceContext:
	default:
		return fmt.Errorf("invalid source %q", predicate.Source)
	}
	if strings.TrimSpace(predicate.Key) == "" {
		return fmt.Errorf("key is required")
	}
	operator := strings.ToLower(strings.TrimSpace(string(predicate.Operator)))
	if operator == "" {
		operator = string(abacOperatorEquals)
	}
	switch abacOperator(operator) {
	case abacOperatorEquals:
		if strings.TrimSpace(predicate.Value) == "" {
			return fmt.Errorf("equals operator requires value")
		}
	case abacOperatorOneOf:
		hasValue := false
		for _, value := range predicate.Values {
			if strings.TrimSpace(value) == "" {
				continue
			}
			hasValue = true
			break
		}
		if !hasValue {
			return fmt.Errorf("one_of operator requires values")
		}
	case abacOperatorEqualsAttribute:
		compareSource := strings.ToLower(strings.TrimSpace(string(predicate.CompareSource)))
		switch abacAttributeSource(compareSource) {
		case abacAttributeSourceSubject, abacAttributeSourceResource, abacAttributeSourceContext:
		default:
			return fmt.Errorf("equals_attribute requires valid compare_source")
		}
		if strings.TrimSpace(predicate.CompareKey) == "" {
			return fmt.Errorf("equals_attribute requires compare_key")
		}
	default:
		return fmt.Errorf("unsupported operator %q", predicate.Operator)
	}
	return nil
}

func validateReBACActionPolicy(policy rebacActionPolicy, path string) error {
	for pathIndex, relationPath := range policy.AnyOf {
		if len(relationPath.Relations) == 0 {
			return fmt.Errorf("%s.any_of[%d]: relations are required", path, pathIndex)
		}
		for relationIndex, relation := range relationPath.Relations {
			normalizedRelation := strings.ToLower(strings.TrimSpace(relation))
			if !isSupportedReBACRelation(normalizedRelation) {
				return fmt.Errorf("%s.any_of[%d].relations[%d]: unsupported relation %q", path, pathIndex, relationIndex, relation)
			}
		}
		for conditionIndex, condition := range relationPath.AllOf {
			if err := validateABACPredicate(condition); err != nil {
				return fmt.Errorf("%s.any_of[%d].all_of[%d]: %w", path, pathIndex, conditionIndex, err)
			}
		}
	}
	return nil
}

func validateAuthzPolicyRolloutActivation(ctx context.Context, store db.Store, policySetID string, rollout db.AuthzPolicyRollout) error {
	if store == nil {
		return fmt.Errorf("policy store is required")
	}
	normalizedPolicySetID := strings.ToLower(strings.TrimSpace(policySetID))
	if normalizedPolicySetID == "" {
		return fmt.Errorf("policy set id is required")
	}
	if rollout.ActiveVersion != nil {
		if err := validateAuthzPolicyVersionBundle(ctx, store, normalizedPolicySetID, *rollout.ActiveVersion); err != nil {
			return fmt.Errorf("active version validation failed: %w", err)
		}
	}
	if rollout.CandidateVersion != nil {
		if err := validateAuthzPolicyVersionBundle(ctx, store, normalizedPolicySetID, *rollout.CandidateVersion); err != nil {
			return fmt.Errorf("candidate version validation failed: %w", err)
		}
	}
	rolloutMode := strings.ToLower(strings.TrimSpace(rollout.Mode))
	if rolloutMode == db.AuthzPolicyRolloutModeEnforce {
		if rollout.ActiveVersion != nil && !hasValidatedVersion(rollout.ValidatedVersions, *rollout.ActiveVersion) {
			return fmt.Errorf("active version must exist in validated_versions for enforce mode")
		}
		if rollout.CandidateVersion != nil && !hasValidatedVersion(rollout.ValidatedVersions, *rollout.CandidateVersion) {
			return fmt.Errorf("candidate version must exist in validated_versions for enforce mode")
		}
	}
	return nil
}

func validateAuthzPolicyVersionBundle(ctx context.Context, store db.Store, policySetID string, version int) error {
	if version <= 0 {
		return fmt.Errorf("version must be greater than zero")
	}
	record, err := store.GetAuthzPolicyVersion(ctx, policySetID, version)
	if err != nil {
		return err
	}
	if _, err := compileRouteAuthorizationPolicyBundleJSON(record.Bundle); err != nil {
		return fmt.Errorf("%w: %v", errInvalidAuthzPolicyVersionBundle, err)
	}
	return nil
}

func hasValidatedVersion(values []int, version int) bool {
	for _, candidate := range values {
		if candidate == version {
			return true
		}
	}
	return false
}

func defaultBuiltInRouteAuthorizationPolicyBundle() routeAuthorizationPolicyBundle {
	return routeAuthorizationPolicyBundle{
		SchemaVersion:  routeAuthorizationPolicyBundleSchemaV1,
		RoutePolicies:  defaultBuiltInRoutePolicyDefinitions(),
		RBACActionRole: defaultRouteActionRoleGrants(),
		ABACPolicies:   defaultRouteActionABACPolicies(),
		ReBACPolicies:  defaultRouteActionReBACPolicies(),
	}
}

func defaultBuiltInRoutePolicyDefinitions() []routePolicyDefinition {
	return []routePolicyDefinition{
		{Method: http.MethodGet, Path: "/v1/findings", Action: policyActionFindingsRead, ResourceType: "finding"},
		{Method: http.MethodGet, Path: "/v1/findings/:finding_id", Action: policyActionFindingsRead, ResourceType: "finding", ResourceIDParam: "finding_id"},
		{Method: http.MethodGet, Path: "/v1/findings/:finding_id/history", Action: policyActionFindingsRead, ResourceType: "finding_history", ResourceIDParam: "finding_id"},
		{Method: http.MethodGet, Path: "/v1/findings/:finding_id/exports", Action: policyActionFindingsRead, ResourceType: "finding_export", ResourceIDParam: "finding_id"},
		{Method: http.MethodGet, Path: "/v1/findings/trends", Action: policyActionFindingsRead, ResourceType: "finding_trend"},
		{Method: http.MethodGet, Path: "/v1/findings/summary", Action: policyActionFindingsRead, ResourceType: "finding_summary"},
		{Method: http.MethodPatch, Path: "/v1/findings/:finding_id/triage", Action: policyActionFindingsTriage, ResourceType: "finding", ResourceIDParam: "finding_id"},
		{Method: http.MethodGet, Path: "/v1/identities", Action: policyActionGraphRead, ResourceType: "identity"},
		{Method: http.MethodGet, Path: "/v1/relationships", Action: policyActionGraphRead, ResourceType: "relationship"},
		{Method: http.MethodGet, Path: "/v1/ownership/signals", Action: policyActionGraphRead, ResourceType: "ownership_signal"},
		{Method: http.MethodGet, Path: "/v1/scans", Action: policyActionScansRead, ResourceType: "scan"},
		{Method: http.MethodGet, Path: "/v1/scans/:scan_id/diff", Action: policyActionScansRead, ResourceType: "scan_diff", ResourceIDParam: "scan_id"},
		{Method: http.MethodGet, Path: "/v1/scans/:scan_id/events", Action: policyActionScansRead, ResourceType: "scan_event", ResourceIDParam: "scan_id"},
		{Method: http.MethodPost, Path: "/v1/scans", Action: policyActionScansRun, ResourceType: "scan"},
		{Method: http.MethodGet, Path: "/v1/repo-scans", Action: policyActionRepoScansRead, ResourceType: "repo_scan"},
		{Method: http.MethodGet, Path: "/v1/repo-scans/:repo_scan_id", Action: policyActionRepoScansRead, ResourceType: "repo_scan", ResourceIDParam: "repo_scan_id"},
		{Method: http.MethodGet, Path: "/v1/repo-findings", Action: policyActionRepoScansRead, ResourceType: "repo_finding"},
		{Method: http.MethodPost, Path: "/v1/repo-scans", Action: policyActionRepoScansRun, ResourceType: "repo_scan"},
		{Method: http.MethodPost, Path: "/v1/authz/policies/simulate", Action: policyActionAuthzSimulate, ResourceType: "authz_policy"},
		{Method: http.MethodPost, Path: "/v1/authz/policies/rollback", Action: policyActionAuthzRollback, ResourceType: "authz_policy"},
	}
}

func validHTTPMethods() map[string]struct{} {
	return map[string]struct{}{
		http.MethodGet:     {},
		http.MethodHead:    {},
		http.MethodPost:    {},
		http.MethodPut:     {},
		http.MethodPatch:   {},
		http.MethodDelete:  {},
		http.MethodOptions: {},
	}
}
