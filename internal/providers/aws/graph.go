package aws

import (
	"context"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

// RelationshipOption customizes graph relationship builder behavior.
type RelationshipOption func(*RelationshipBuilder)

// RelationshipBuilder constructs graph edges from normalized data and permissions.
type RelationshipBuilder struct {
	now func() time.Time
}

var _ providers.RelationshipResolver = (*RelationshipBuilder)(nil)

// NewRelationshipBuilder returns the AWS relationship resolver.
func NewRelationshipBuilder(opts ...RelationshipOption) *RelationshipBuilder {
	builder := &RelationshipBuilder{now: time.Now}
	for _, opt := range opts {
		opt(builder)
	}
	return builder
}

// WithRelationshipClock injects a deterministic clock for tests.
func WithRelationshipClock(now func() time.Time) RelationshipOption {
	return func(builder *RelationshipBuilder) {
		if now != nil {
			builder.now = now
		}
	}
}

// ResolveRelationships creates policy attachment, trust, and can_access edges.
func (b *RelationshipBuilder) ResolveRelationships(ctx context.Context, bundle providers.NormalizedBundle, perms []providers.PermissionTuple) ([]domain.Relationship, error) {
	timestamp := b.now().UTC()
	relationships := make([]domain.Relationship, 0, len(bundle.Policies)+len(perms))
	seen := map[string]struct{}{}

	arnToIdentity := make(map[string]string, len(bundle.Identities))
	for _, identity := range bundle.Identities {
		arnToIdentity[identity.ARN] = identity.ID
	}

	for _, policy := range bundle.Policies {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		policyType, _ := policy.Normalized[policyTypeKey].(string)
		identityID, _ := policy.Normalized[identityIDKey].(string)
		if identityID == "" {
			continue
		}

		switch policyType {
		case policyTypePerm:
			relationship := domain.Relationship{
				ID:           relationshipID(domain.RelationshipAttachedPolicy, identityID, policy.ID),
				Type:         domain.RelationshipAttachedPolicy,
				FromNodeID:   identityID,
				ToNodeID:     policy.ID,
				EvidenceRef:  policy.RawRef,
				DiscoveredAt: timestamp,
			}
			appendRelationship(&relationships, seen, relationship)
		case policyTypeTrust:
			principals := parseStringList(policy.Normalized[principalsKey])
			for _, principal := range principals {
				fromNodeID := principalNodeID(principal, arnToIdentity)
				if fromNodeID == "" {
					continue
				}
				relationship := domain.Relationship{
					ID:           relationshipID(domain.RelationshipCanAssume, fromNodeID, identityID),
					Type:         domain.RelationshipCanAssume,
					FromNodeID:   fromNodeID,
					ToNodeID:     identityID,
					EvidenceRef:  policy.RawRef,
					DiscoveredAt: timestamp,
				}
				appendRelationship(&relationships, seen, relationship)
			}
		}
	}

	for _, permission := range perms {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if permission.Effect != "Allow" {
			continue
		}
		toNodeID := accessNodeID(permission.Action, permission.Resource)
		relationship := domain.Relationship{
			ID:           relationshipID(domain.RelationshipCanAccess, permission.IdentityID, toNodeID),
			Type:         domain.RelationshipCanAccess,
			FromNodeID:   permission.IdentityID,
			ToNodeID:     toNodeID,
			EvidenceRef:  permission.Action,
			DiscoveredAt: timestamp,
		}
		appendRelationship(&relationships, seen, relationship)
	}

	return relationships, nil
}

func appendRelationship(destination *[]domain.Relationship, seen map[string]struct{}, relationship domain.Relationship) {
	if relationship.FromNodeID == "" || relationship.ToNodeID == "" {
		return
	}
	if _, exists := seen[relationship.ID]; exists {
		return
	}
	seen[relationship.ID] = struct{}{}
	*destination = append(*destination, relationship)
}
