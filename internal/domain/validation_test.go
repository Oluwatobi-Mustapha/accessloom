package domain

import "testing"

func TestIdentityValidate(t *testing.T) {
	valid := Identity{ID: "1", Provider: ProviderAWS, Type: IdentityTypeRole, Name: "role-a"}
	if !valid.Validate() {
		t.Fatal("expected valid identity")
	}
	invalid := Identity{ID: "1", Provider: ProviderAWS, Type: IdentityTypeRole, Name: "   "}
	if invalid.Validate() {
		t.Fatal("expected invalid identity")
	}
}

func TestRelationshipValidate(t *testing.T) {
	valid := Relationship{ID: "1", Type: RelationshipCanAssume, FromNodeID: "a", ToNodeID: "b"}
	if !valid.Validate() {
		t.Fatal("expected valid relationship")
	}
	invalid := Relationship{ID: "1", Type: RelationshipCanAssume, FromNodeID: "", ToNodeID: "b"}
	if invalid.Validate() {
		t.Fatal("expected invalid relationship")
	}
	invalidType := Relationship{ID: "1", Type: RelationshipType("custom_rel"), FromNodeID: "a", ToNodeID: "b"}
	if invalidType.Validate() {
		t.Fatal("expected invalid relationship type")
	}
}

func TestFindingValidate(t *testing.T) {
	valid := Finding{ID: "1", Type: FindingEscalationPath, Severity: SeverityHigh, Title: "Escalation path found"}
	if !valid.Validate() {
		t.Fatal("expected valid finding")
	}
	invalid := Finding{ID: "1", Type: FindingEscalationPath, Severity: SeverityHigh, Title: "  "}
	if invalid.Validate() {
		t.Fatal("expected invalid finding")
	}
}
