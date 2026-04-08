package api

import (
	"context"
	"fmt"
	"strings"
)

const (
	policyContextTenantIDKey    = "tenant_id"
	policyContextWorkspaceIDKey = "workspace_id"

	policyAttributeOwnerTeam      = "owner_team"
	policyAttributeEnvironment    = "env"
	policyAttributeRiskTier       = "risk_tier"
	policyAttributeClassification = "classification"
)

type abacAttributeSource string

type abacOperator string

const (
	abacAttributeSourceSubject  abacAttributeSource = "subject"
	abacAttributeSourceResource abacAttributeSource = "resource"
	abacAttributeSourceContext  abacAttributeSource = "context"

	abacOperatorEquals          abacOperator = "equals"
	abacOperatorOneOf           abacOperator = "one_of"
	abacOperatorEqualsAttribute abacOperator = "equals_attribute"
)

// tenantIsolationEvaluator enforces tenant/workspace scope boundaries before policy grants.
type tenantIsolationEvaluator struct{}

func newTenantIsolationEvaluator() PolicyEvaluator {
	return tenantIsolationEvaluator{}
}

func (tenantIsolationEvaluator) Evaluate(_ context.Context, input PolicyInput) (PolicyOutcome, string, error) {
	subjectTenant := strings.TrimSpace(input.Subject.TenantID)
	subjectWorkspace := strings.TrimSpace(input.Subject.WorkspaceID)

	targetTenant := strings.TrimSpace(input.Resource.TenantID)
	if targetTenant == "" {
		targetTenant = strings.TrimSpace(input.Context.Attributes[policyContextTenantIDKey])
	}
	targetWorkspace := strings.TrimSpace(input.Resource.WorkspaceID)
	if targetWorkspace == "" {
		targetWorkspace = strings.TrimSpace(input.Context.Attributes[policyContextWorkspaceIDKey])
	}

	if subjectTenant != "" && targetTenant != "" && subjectTenant != targetTenant {
		return PolicyOutcomeDeny, fmt.Sprintf("tenant scope mismatch: subject=%q target=%q", subjectTenant, targetTenant), nil
	}
	if subjectWorkspace != "" && targetWorkspace != "" && subjectWorkspace != targetWorkspace {
		return PolicyOutcomeDeny, fmt.Sprintf("workspace scope mismatch: subject=%q target=%q", subjectWorkspace, targetWorkspace), nil
	}
	return PolicyOutcomeNoOpinion, "", nil
}

// rbacPolicyEvaluator resolves subject roles against action grants.
type rbacPolicyEvaluator struct {
	actionRoles map[string]map[string]struct{}
}

// rbacRequirementEvaluator enforces that mapped actions have at least one granted role.
type rbacRequirementEvaluator struct {
	actionRoles map[string]map[string]struct{}
}

// newRBACPolicyEvaluator builds one RBAC evaluator from action->roles grants.
func newRBACPolicyEvaluator(grants map[string][]string) PolicyEvaluator {
	return &rbacPolicyEvaluator{actionRoles: normalizeActionRoleGrants(grants)}
}

// newRBACRequirementEvaluator builds one RBAC gate that denies mapped actions when no role grant exists.
func newRBACRequirementEvaluator(grants map[string][]string) PolicyEvaluator {
	return &rbacRequirementEvaluator{actionRoles: normalizeActionRoleGrants(grants)}
}

func (e *rbacPolicyEvaluator) Evaluate(_ context.Context, input PolicyInput) (PolicyOutcome, string, error) {
	if e == nil || len(e.actionRoles) == 0 {
		return PolicyOutcomeNoOpinion, "", nil
	}
	action := strings.ToLower(strings.TrimSpace(input.Action))
	if action == "" {
		return PolicyOutcomeNoOpinion, "", nil
	}
	allowedRoles, exists := e.actionRoles[action]
	if !exists {
		return PolicyOutcomeNoOpinion, "", nil
	}
	if subjectHasAnyRole(input.Subject.Roles, allowedRoles) {
		return PolicyOutcomeAllow, "rbac role grants action", nil
	}
	return PolicyOutcomeNoOpinion, "", nil
}

func (e *rbacRequirementEvaluator) Evaluate(_ context.Context, input PolicyInput) (PolicyOutcome, string, error) {
	if e == nil || len(e.actionRoles) == 0 {
		return PolicyOutcomeNoOpinion, "", nil
	}
	action := strings.ToLower(strings.TrimSpace(input.Action))
	if action == "" {
		return PolicyOutcomeNoOpinion, "", nil
	}
	allowedRoles, exists := e.actionRoles[action]
	if !exists {
		return PolicyOutcomeNoOpinion, "", nil
	}
	if subjectHasAnyRole(input.Subject.Roles, allowedRoles) {
		return PolicyOutcomeNoOpinion, "", nil
	}
	return PolicyOutcomeDeny, "rbac role does not grant action", nil
}

func normalizeActionRoleGrants(grants map[string][]string) map[string]map[string]struct{} {
	actionRoles := make(map[string]map[string]struct{}, len(grants))
	for action, roles := range grants {
		normalizedAction := strings.ToLower(strings.TrimSpace(action))
		if normalizedAction == "" {
			continue
		}
		roleSet := map[string]struct{}{}
		for _, role := range roles {
			normalizedRole := strings.ToLower(strings.TrimSpace(role))
			if normalizedRole == "" {
				continue
			}
			roleSet[normalizedRole] = struct{}{}
		}
		if len(roleSet) > 0 {
			actionRoles[normalizedAction] = roleSet
		}
	}
	return actionRoles
}

func subjectHasAnyRole(roles []string, allowedRoles map[string]struct{}) bool {
	for _, role := range roles {
		normalizedRole := strings.ToLower(strings.TrimSpace(role))
		if normalizedRole == "" {
			continue
		}
		if _, ok := allowedRoles[normalizedRole]; ok {
			return true
		}
	}
	return false
}

type abacPredicate struct {
	Source        abacAttributeSource
	Key           string
	Operator      abacOperator
	Value         string
	Values        []string
	CompareSource abacAttributeSource
	CompareKey    string
}

type abacClause struct {
	AllOf []abacPredicate
}

type abacActionPolicy struct {
	AnyOf []abacClause
}

type abacPolicyEvaluator struct {
	actionPolicies map[string]abacActionPolicy
}

func newABACPolicyEvaluator(policies map[string]abacActionPolicy) PolicyEvaluator {
	return &abacPolicyEvaluator{actionPolicies: normalizeABACPolicies(policies)}
}

func normalizeABACPolicies(policies map[string]abacActionPolicy) map[string]abacActionPolicy {
	normalized := make(map[string]abacActionPolicy, len(policies))
	for action, policy := range policies {
		normalizedAction := strings.ToLower(strings.TrimSpace(action))
		if normalizedAction == "" {
			continue
		}
		normalized[normalizedAction] = normalizeABACPolicy(policy)
	}
	return normalized
}

func normalizeABACPolicy(policy abacActionPolicy) abacActionPolicy {
	result := abacActionPolicy{AnyOf: make([]abacClause, 0, len(policy.AnyOf))}
	for _, clause := range policy.AnyOf {
		normalizedClause := abacClause{AllOf: make([]abacPredicate, 0, len(clause.AllOf))}
		for _, predicate := range clause.AllOf {
			normalizedClause.AllOf = append(normalizedClause.AllOf, normalizeABACPredicate(predicate))
		}
		result.AnyOf = append(result.AnyOf, normalizedClause)
	}
	return result
}

func normalizeABACPredicate(predicate abacPredicate) abacPredicate {
	result := predicate
	result.Source = abacAttributeSource(strings.ToLower(strings.TrimSpace(string(predicate.Source))))
	result.Key = strings.ToLower(strings.TrimSpace(predicate.Key))
	result.Operator = abacOperator(strings.ToLower(strings.TrimSpace(string(predicate.Operator))))
	result.Value = strings.TrimSpace(predicate.Value)
	result.CompareSource = abacAttributeSource(strings.ToLower(strings.TrimSpace(string(predicate.CompareSource))))
	result.CompareKey = strings.ToLower(strings.TrimSpace(predicate.CompareKey))

	values := make([]string, 0, len(predicate.Values))
	seen := map[string]struct{}{}
	for _, value := range predicate.Values {
		normalizedValue := strings.TrimSpace(value)
		if normalizedValue == "" {
			continue
		}
		if _, exists := seen[normalizedValue]; exists {
			continue
		}
		seen[normalizedValue] = struct{}{}
		values = append(values, normalizedValue)
	}
	result.Values = values
	if result.Operator == "" {
		result.Operator = abacOperatorEquals
	}
	return result
}

func (e *abacPolicyEvaluator) Evaluate(_ context.Context, input PolicyInput) (PolicyOutcome, string, error) {
	if e == nil || len(e.actionPolicies) == 0 {
		return PolicyOutcomeNoOpinion, "", nil
	}
	action := strings.ToLower(strings.TrimSpace(input.Action))
	if action == "" {
		return PolicyOutcomeNoOpinion, "", nil
	}
	policy, exists := e.actionPolicies[action]
	if !exists {
		return PolicyOutcomeNoOpinion, "", nil
	}
	if len(policy.AnyOf) == 0 {
		return PolicyOutcomeAllow, "abac policy grants action", nil
	}

	denyReason := "abac conditions not satisfied"
	for _, clause := range policy.AnyOf {
		clauseMatched := true
		for _, predicate := range clause.AllOf {
			matches, reason := evaluateABACPredicate(input, predicate)
			if matches {
				continue
			}
			clauseMatched = false
			if strings.TrimSpace(reason) != "" {
				denyReason = reason
			}
			break
		}
		if clauseMatched {
			return PolicyOutcomeAllow, "abac policy grants action", nil
		}
	}
	return PolicyOutcomeDeny, denyReason, nil
}

func evaluateABACPredicate(input PolicyInput, predicate abacPredicate) (bool, string) {
	left, ok := resolveABACValue(input, predicate.Source, predicate.Key)
	if !ok {
		return false, fmt.Sprintf("abac missing %s.%s", predicate.Source, predicate.Key)
	}

	switch predicate.Operator {
	case abacOperatorEquals:
		if left == predicate.Value {
			return true, ""
		}
		return false, fmt.Sprintf("abac mismatch %s.%s", predicate.Source, predicate.Key)
	case abacOperatorOneOf:
		for _, candidate := range predicate.Values {
			if left == candidate {
				return true, ""
			}
		}
		return false, fmt.Sprintf("abac value not allowed for %s.%s", predicate.Source, predicate.Key)
	case abacOperatorEqualsAttribute:
		right, exists := resolveABACValue(input, predicate.CompareSource, predicate.CompareKey)
		if !exists {
			return false, fmt.Sprintf("abac missing %s.%s", predicate.CompareSource, predicate.CompareKey)
		}
		if left == right {
			return true, ""
		}
		return false, fmt.Sprintf("abac mismatch %s.%s vs %s.%s", predicate.Source, predicate.Key, predicate.CompareSource, predicate.CompareKey)
	default:
		return false, "abac unsupported operator"
	}
}

func resolveABACValue(input PolicyInput, source abacAttributeSource, key string) (string, bool) {
	normalizedKey := strings.ToLower(strings.TrimSpace(key))
	if normalizedKey == "" {
		return "", false
	}

	switch source {
	case abacAttributeSourceSubject:
		switch normalizedKey {
		case "type":
			value := strings.TrimSpace(input.Subject.Type)
			return value, value != ""
		case "id":
			value := strings.TrimSpace(input.Subject.ID)
			return value, value != ""
		case "tenant_id":
			value := strings.TrimSpace(input.Subject.TenantID)
			return value, value != ""
		case "workspace_id":
			value := strings.TrimSpace(input.Subject.WorkspaceID)
			return value, value != ""
		default:
			return lookupPolicyAttribute(input.Subject.Attributes, normalizedKey)
		}
	case abacAttributeSourceResource:
		switch normalizedKey {
		case "type":
			value := strings.TrimSpace(input.Resource.Type)
			return value, value != ""
		case "id":
			value := strings.TrimSpace(input.Resource.ID)
			return value, value != ""
		case "tenant_id":
			value := strings.TrimSpace(input.Resource.TenantID)
			return value, value != ""
		case "workspace_id":
			value := strings.TrimSpace(input.Resource.WorkspaceID)
			return value, value != ""
		default:
			return lookupPolicyAttribute(input.Resource.Attributes, normalizedKey)
		}
	case abacAttributeSourceContext:
		switch normalizedKey {
		case "request_path":
			value := strings.TrimSpace(input.Context.RequestPath)
			return value, value != ""
		case "request_method":
			value := strings.TrimSpace(input.Context.RequestMethod)
			return value, value != ""
		default:
			return lookupPolicyAttribute(input.Context.Attributes, normalizedKey)
		}
	default:
		return "", false
	}
}

func lookupPolicyAttribute(attributes map[string]string, key string) (string, bool) {
	if len(attributes) == 0 {
		return "", false
	}
	if value, exists := attributes[key]; exists {
		trimmed := strings.TrimSpace(value)
		return trimmed, trimmed != ""
	}
	for existingKey, value := range attributes {
		if !strings.EqualFold(existingKey, key) {
			continue
		}
		trimmed := strings.TrimSpace(value)
		return trimmed, trimmed != ""
	}
	return "", false
}
