package aws

import (
	"context"
	"fmt"

	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

// PolicyPermissionResolver expands normalized policy statements into permission tuples.
type PolicyPermissionResolver struct{}

var _ providers.PermissionResolver = (*PolicyPermissionResolver)(nil)

// NewPolicyPermissionResolver returns the AWS permission resolver.
func NewPolicyPermissionResolver() *PolicyPermissionResolver {
	return &PolicyPermissionResolver{}
}

// ResolvePermissions materializes semantic permissions for graph analysis.
func (r *PolicyPermissionResolver) ResolvePermissions(ctx context.Context, bundle providers.NormalizedBundle) ([]providers.PermissionTuple, error) {
	tuples := make([]providers.PermissionTuple, 0, len(bundle.Policies)*4)
	seen := map[string]struct{}{}

	for _, policy := range bundle.Policies {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		policyType, _ := policy.Normalized[policyTypeKey].(string)
		if policyType != policyTypePerm {
			continue
		}

		identityID, _ := policy.Normalized[identityIDKey].(string)
		if identityID == "" {
			return nil, fmt.Errorf("policy %s missing identity_id", policy.ID)
		}

		statements, err := parseNormalizedStatements(policy.Normalized[statementsKey])
		if err != nil {
			return nil, fmt.Errorf("policy %s invalid statements: %w", policy.ID, err)
		}

		for _, statement := range statements {
			effect, _ := statement["effect"].(string)
			actions := parseStringList(statement["actions"])
			resources := parseStringList(statement["resources"])

			for _, action := range actions {
				for _, resource := range resources {
					tuple := providers.PermissionTuple{
						IdentityID: identityID,
						Action:     action,
						Resource:   resource,
						Effect:     effect,
					}
					key := tuple.IdentityID + "|" + tuple.Action + "|" + tuple.Resource + "|" + tuple.Effect
					if _, exists := seen[key]; exists {
						continue
					}
					seen[key] = struct{}{}
					tuples = append(tuples, tuple)
				}
			}
		}
	}

	return tuples, nil
}

func parseNormalizedStatements(raw any) ([]map[string]any, error) {
	switch typed := raw.(type) {
	case []map[string]any:
		return typed, nil
	case []any:
		statements := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			statement, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("statement has unexpected type %T", item)
			}
			statements = append(statements, statement)
		}
		return statements, nil
	default:
		return nil, fmt.Errorf("expected statement array, got %T", raw)
	}
}
