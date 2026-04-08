package api

import (
	"context"
	"fmt"
	"strings"
)

const (
	policyContextTenantIDKey    = "tenant_id"
	policyContextWorkspaceIDKey = "workspace_id"
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

// newRBACPolicyEvaluator builds one RBAC evaluator from action->roles grants.
func newRBACPolicyEvaluator(grants map[string][]string) PolicyEvaluator {
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
	return &rbacPolicyEvaluator{actionRoles: actionRoles}
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
	for _, role := range input.Subject.Roles {
		normalizedRole := strings.ToLower(strings.TrimSpace(role))
		if normalizedRole == "" {
			continue
		}
		if _, ok := allowedRoles[normalizedRole]; ok {
			return PolicyOutcomeAllow, "rbac role grants action", nil
		}
	}
	return PolicyOutcomeNoOpinion, "", nil
}
