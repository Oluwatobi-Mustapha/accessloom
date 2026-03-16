package kubernetes

import (
	"context"
	"fmt"

	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

// PermissionResolver expands normalized role-binding statements into permission tuples.
type PermissionResolver struct{}

var _ providers.PermissionResolver = (*PermissionResolver)(nil)

// NewPermissionResolver returns the Kubernetes permission resolver.
func NewPermissionResolver() *PermissionResolver { return &PermissionResolver{} }

// ResolvePermissions materializes permission tuples used by graph and rules.
func (r *PermissionResolver) ResolvePermissions(ctx context.Context, bundle providers.NormalizedBundle) ([]providers.PermissionTuple, error) {
	tuples := []providers.PermissionTuple{}
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
		statements, err := parseStatements(policy.Normalized[statementsKey])
		if err != nil {
			return nil, fmt.Errorf("policy %s invalid statements: %w", policy.ID, err)
		}
		for _, statement := range statements {
			effect, _ := statement["effect"].(string)
			actions := parseStringList(statement["actions"])
			resources := parseStringList(statement["resources"])
			for _, action := range actions {
				for _, resource := range resources {
					tuple := providers.PermissionTuple{IdentityID: identityID, Action: action, Resource: resource, Effect: effect}
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

func parseStatements(raw any) ([]map[string]any, error) {
	switch typed := raw.(type) {
	case []map[string]any:
		return typed, nil
	case []any:
		result := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			statement, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("statement has unexpected type %T", item)
			}
			result = append(result, statement)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("expected statement array, got %T", raw)
	}
}

func parseStringList(raw any) []string {
	switch typed := raw.(type) {
	case []string:
		return typed
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			value, ok := item.(string)
			if ok && value != "" {
				result = append(result, value)
			}
		}
		return result
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	default:
		return nil
	}
}
