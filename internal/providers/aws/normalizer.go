package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

const (
	policyTypeKey   = "policy_type"
	policyTypePerm  = "permission"
	policyTypeTrust = "trust"
	identityIDKey   = "identity_id"
	statementsKey   = "statements"
	principalsKey   = "principals"
)

// RoleNormalizer transforms raw IAM role assets into provider-agnostic entities.
type RoleNormalizer struct{}

var _ providers.Normalizer = (*RoleNormalizer)(nil)

// NewRoleNormalizer returns the AWS role normalizer.
func NewRoleNormalizer() *RoleNormalizer {
	return &RoleNormalizer{}
}

// Normalize converts IAM role assets to normalized identities and policies.
func (n *RoleNormalizer) Normalize(ctx context.Context, raw []providers.RawAsset) (providers.NormalizedBundle, error) {
	bundle := providers.NormalizedBundle{
		Identities: make([]domain.Identity, 0, len(raw)),
		Policies:   make([]domain.Policy, 0, len(raw)*2),
	}

	identitySeen := map[string]struct{}{}
	policySeen := map[string]struct{}{}

	for i, asset := range raw {
		if err := ctx.Err(); err != nil {
			return providers.NormalizedBundle{}, err
		}
		if asset.Kind != "iam_role" {
			continue
		}

		var role IAMRole
		if err := json.Unmarshal(asset.Payload, &role); err != nil {
			return providers.NormalizedBundle{}, fmt.Errorf("decode iam role asset[%d]: %w", i, err)
		}
		arn := strings.TrimSpace(role.ARN)
		if arn == "" {
			continue
		}

		identityID := identityIDFromARN(arn)
		if _, exists := identitySeen[identityID]; !exists {
			identitySeen[identityID] = struct{}{}
			bundle.Identities = append(bundle.Identities, domain.Identity{
				ID:         identityID,
				Provider:   domain.ProviderAWS,
				Type:       domain.IdentityTypeRole,
				Name:       strings.TrimSpace(role.Name),
				ARN:        arn,
				OwnerHint:  ownerHintFromTags(role.Tags),
				CreatedAt:  derefTimeOrZero(role.CreatedAt),
				LastUsedAt: role.LastUsedAt,
				Tags:       copyTags(role.Tags),
				RawRef:     asset.SourceID,
			})
		}

		permissionPolicies, err := normalizePermissionPolicies(identityID, role.PermissionPolicies)
		if err != nil {
			return providers.NormalizedBundle{}, fmt.Errorf("normalize permission policies for %s: %w", arn, err)
		}
		for _, policy := range permissionPolicies {
			if _, exists := policySeen[policy.ID]; exists {
				continue
			}
			policySeen[policy.ID] = struct{}{}
			bundle.Policies = append(bundle.Policies, policy)
		}

		trustPolicy, err := normalizeTrustPolicy(identityID, role.AssumeRolePolicyDocument)
		if err != nil {
			return providers.NormalizedBundle{}, fmt.Errorf("normalize trust policy for %s: %w", arn, err)
		}
		if trustPolicy != nil {
			if _, exists := policySeen[trustPolicy.ID]; !exists {
				policySeen[trustPolicy.ID] = struct{}{}
				bundle.Policies = append(bundle.Policies, *trustPolicy)
			}
		}
	}

	return bundle, nil
}

func normalizePermissionPolicies(identityID string, policies []IAMPermissionPolicy) ([]domain.Policy, error) {
	result := make([]domain.Policy, 0, len(policies))
	for idx, policy := range policies {
		doc, err := parsePolicyDocument(policy.Document)
		if err != nil {
			return nil, fmt.Errorf("policy %q: %w", policy.Name, err)
		}

		statements := make([]map[string]any, 0, len(doc.Statement))
		for _, statement := range doc.Statement {
			actions := parseStringList(statement.Action)
			resources := parseStringList(statement.Resource)
			if len(actions) == 0 || len(resources) == 0 {
				continue
			}
			statements = append(statements, normalizedStatement(statement.Effect, actions, resources))
		}
		if len(statements) == 0 {
			continue
		}

		policyID := permissionPolicyID(identityID, policy.Name, idx)
		result = append(result, domain.Policy{
			ID:       policyID,
			Provider: domain.ProviderAWS,
			Name:     policy.Name,
			Document: []byte(policy.Document),
			Normalized: map[string]any{
				policyTypeKey: policyTypePerm,
				identityIDKey: identityID,
				statementsKey: statements,
			},
			RawRef: identityID,
		})
	}
	return result, nil
}

func normalizeTrustPolicy(identityID, rawTrustDocument string) (*domain.Policy, error) {
	doc, err := parsePolicyDocument(rawTrustDocument)
	if err != nil {
		return nil, err
	}
	if len(doc.Statement) == 0 {
		return nil, nil
	}

	principals := make([]string, 0, len(doc.Statement))
	for _, statement := range doc.Statement {
		if !strings.EqualFold(statement.Effect, "allow") {
			continue
		}
		principals = append(principals, parseAWSPrincipals(statement.Principal)...)
	}
	principals = dedupeStrings(principals)
	if len(principals) == 0 {
		return nil, nil
	}

	return &domain.Policy{
		ID:       trustPolicyID(identityID),
		Provider: domain.ProviderAWS,
		Name:     "assume-role-trust",
		Document: []byte(rawTrustDocument),
		Normalized: map[string]any{
			policyTypeKey: policyTypeTrust,
			identityIDKey: identityID,
			principalsKey: principals,
		},
		RawRef: identityID,
	}, nil
}

func ownerHintFromTags(tags map[string]string) string {
	if tags == nil {
		return ""
	}
	for _, key := range []string{"owner", "team", "service"} {
		if value := strings.TrimSpace(tags[key]); value != "" {
			return value
		}
	}
	return ""
}

func copyTags(tags map[string]string) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	copied := make(map[string]string, len(tags))
	for key, value := range tags {
		copied[key] = value
	}
	return copied
}
