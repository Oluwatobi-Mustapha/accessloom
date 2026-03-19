package domain

import "strings"

var supportedRelationshipTypes = map[RelationshipType]struct{}{
	RelationshipCanAssume:      {},
	RelationshipAttachedPolicy: {},
	RelationshipAttachedTo:     {},
	RelationshipBoundTo:        {},
	RelationshipCanAccess:      {},
	RelationshipCanImpersonate: {},
}

// IsSupportedRelationshipType reports whether the relationship semantic is part
// of the v1 graph contract.
func IsSupportedRelationshipType(rel RelationshipType) bool {
	_, ok := supportedRelationshipTypes[rel]
	return ok
}

// Validate ensures the identity has enough information for deduplication and graph linking.
func (i Identity) Validate() bool {
	return i.ID != "" && i.Provider != "" && i.Type != "" && strings.TrimSpace(i.Name) != ""
}

// Validate ensures relationships remain queryable and directionally consistent.
func (r Relationship) Validate() bool {
	return r.ID != "" && IsSupportedRelationshipType(r.Type) && r.FromNodeID != "" && r.ToNodeID != ""
}

// Validate ensures findings are actionable and correctly categorized.
func (f Finding) Validate() bool {
	return f.ID != "" && f.Type != "" && f.Severity != "" && strings.TrimSpace(f.Title) != ""
}
