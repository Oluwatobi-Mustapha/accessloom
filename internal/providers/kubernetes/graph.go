package kubernetes

import (
	"context"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

// RelationshipResolver builds k8s graph edges from workloads and permissions.
type RelationshipResolver struct {
	now func() time.Time
}

var _ providers.RelationshipResolver = (*RelationshipResolver)(nil)

// NewRelationshipResolver creates Kubernetes relationship resolver.
func NewRelationshipResolver() *RelationshipResolver {
	return &RelationshipResolver{now: time.Now}
}

// ResolveRelationships builds bound_to, attached_policy, and can_access edges.
func (r *RelationshipResolver) ResolveRelationships(ctx context.Context, bundle providers.NormalizedBundle, perms []providers.PermissionTuple) ([]domain.Relationship, error) {
	timestamp := r.now().UTC()
	relationships := []domain.Relationship{}
	seen := map[string]struct{}{}

	for _, workload := range bundle.Workloads {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		identityID := workload.RawRef
		if identityID == "" {
			continue
		}
		rel := domain.Relationship{
			ID:           "k8s:rel:bound_to:" + workload.ID + ":" + identityID,
			Type:         domain.RelationshipBoundTo,
			FromNodeID:   workload.ID,
			ToNodeID:     identityID,
			EvidenceRef:  workload.RawRef,
			DiscoveredAt: timestamp,
		}
		appendRelationship(&relationships, seen, rel)
	}

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
			continue
		}
		rel := domain.Relationship{
			ID:           "k8s:rel:attached_policy:" + identityID + ":" + policy.ID,
			Type:         domain.RelationshipAttachedPolicy,
			FromNodeID:   identityID,
			ToNodeID:     policy.ID,
			EvidenceRef:  policy.RawRef,
			DiscoveredAt: timestamp,
		}
		appendRelationship(&relationships, seen, rel)
	}

	for _, permission := range perms {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if permission.Effect != "Allow" {
			continue
		}
		toNodeID := accessNodeID(permission.Action, permission.Resource)
		rel := domain.Relationship{
			ID:           "k8s:rel:can_access:" + permission.IdentityID + ":" + toNodeID,
			Type:         domain.RelationshipCanAccess,
			FromNodeID:   permission.IdentityID,
			ToNodeID:     toNodeID,
			EvidenceRef:  permission.Action,
			DiscoveredAt: timestamp,
		}
		appendRelationship(&relationships, seen, rel)
	}

	return relationships, nil
}

func appendRelationship(dest *[]domain.Relationship, seen map[string]struct{}, relationship domain.Relationship) {
	if relationship.FromNodeID == "" || relationship.ToNodeID == "" {
		return
	}
	if _, exists := seen[relationship.ID]; exists {
		return
	}
	seen[relationship.ID] = struct{}{}
	*dest = append(*dest, relationship)
}
