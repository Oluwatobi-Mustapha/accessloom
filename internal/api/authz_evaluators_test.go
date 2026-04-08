package api

import (
	"context"
	"strings"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
)

func TestTenantIsolationEvaluatorDenyMismatch(t *testing.T) {
	evaluator := newTenantIsolationEvaluator()
	outcome, reason, err := evaluator.Evaluate(context.Background(), PolicyInput{
		Subject: PolicySubject{TenantID: "tenant-a", WorkspaceID: "workspace-a"},
		Action:  "findings.read",
		Resource: PolicyResource{
			TenantID:    "tenant-b",
			WorkspaceID: "workspace-a",
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if outcome != PolicyOutcomeDeny {
		t.Fatalf("expected deny, got %q", outcome)
	}
	if !strings.Contains(reason, "tenant scope mismatch") {
		t.Fatalf("expected tenant mismatch reason, got %q", reason)
	}
}

func TestTenantIsolationEvaluatorDenyCaseVariantIDs(t *testing.T) {
	evaluator := newTenantIsolationEvaluator()
	outcome, reason, err := evaluator.Evaluate(context.Background(), PolicyInput{
		Subject: PolicySubject{TenantID: "Tenant-A", WorkspaceID: "Workspace-A"},
		Action:  "findings.read",
		Resource: PolicyResource{
			TenantID:    "tenant-a",
			WorkspaceID: "workspace-a",
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if outcome != PolicyOutcomeDeny {
		t.Fatalf("expected deny for case-variant IDs, got %q", outcome)
	}
	if !strings.Contains(reason, "tenant scope mismatch") {
		t.Fatalf("expected tenant mismatch reason, got %q", reason)
	}
}

func TestTenantIsolationEvaluatorNoOpinionWhenSubjectScopeMissing(t *testing.T) {
	evaluator := newTenantIsolationEvaluator()
	outcome, reason, err := evaluator.Evaluate(context.Background(), PolicyInput{
		Subject: PolicySubject{},
		Action:  "findings.read",
		Context: PolicyContext{Attributes: map[string]string{
			policyContextTenantIDKey:    "tenant-a",
			policyContextWorkspaceIDKey: "workspace-a",
		}},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if outcome != PolicyOutcomeNoOpinion {
		t.Fatalf("expected no-opinion, got %q", outcome)
	}
	if reason != "" {
		t.Fatalf("expected empty reason for no-opinion, got %q", reason)
	}
}

func TestRBACPolicyEvaluatorAllowWhenRoleGrantsAction(t *testing.T) {
	evaluator := newRBACPolicyEvaluator(map[string][]string{
		"findings.read": {"viewer", "admin"},
	})
	outcome, reason, err := evaluator.Evaluate(context.Background(), PolicyInput{
		Subject: PolicySubject{Roles: []string{"viewer"}},
		Action:  "findings.read",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if outcome != PolicyOutcomeAllow {
		t.Fatalf("expected allow, got %q", outcome)
	}
	if reason == "" {
		t.Fatal("expected allow reason")
	}
}

func TestRBACPolicyEvaluatorNoOpinionWhenRoleMissing(t *testing.T) {
	evaluator := newRBACPolicyEvaluator(map[string][]string{
		"findings.read": {"viewer", "admin"},
	})
	outcome, reason, err := evaluator.Evaluate(context.Background(), PolicyInput{
		Subject: PolicySubject{Roles: []string{"analyst"}},
		Action:  "findings.read",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if outcome != PolicyOutcomeNoOpinion {
		t.Fatalf("expected no-opinion, got %q", outcome)
	}
	if reason != "" {
		t.Fatalf("expected empty reason for no-opinion, got %q", reason)
	}
}

func TestRBACPolicyEvaluatorNoOpinionWhenActionUnmapped(t *testing.T) {
	evaluator := newRBACPolicyEvaluator(map[string][]string{
		"findings.read": {"viewer", "admin"},
	})
	outcome, reason, err := evaluator.Evaluate(context.Background(), PolicyInput{
		Subject: PolicySubject{Roles: []string{"viewer"}},
		Action:  "scans.run",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if outcome != PolicyOutcomeNoOpinion {
		t.Fatalf("expected no-opinion, got %q", outcome)
	}
	if reason != "" {
		t.Fatalf("expected empty reason for no-opinion, got %q", reason)
	}
}

func TestRBACRequirementEvaluatorDenyWhenRoleMissing(t *testing.T) {
	evaluator := newRBACRequirementEvaluator(map[string][]string{
		"findings.read": {"viewer", "admin"},
	})
	outcome, reason, err := evaluator.Evaluate(context.Background(), PolicyInput{
		Subject: PolicySubject{Roles: []string{"analyst"}},
		Action:  "findings.read",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if outcome != PolicyOutcomeDeny {
		t.Fatalf("expected deny, got %q", outcome)
	}
	if strings.TrimSpace(reason) == "" {
		t.Fatal("expected deny reason")
	}
}

func TestRBACRequirementEvaluatorNoOpinionWhenRoleGranted(t *testing.T) {
	evaluator := newRBACRequirementEvaluator(map[string][]string{
		"findings.read": {"viewer", "admin"},
	})
	outcome, reason, err := evaluator.Evaluate(context.Background(), PolicyInput{
		Subject: PolicySubject{Roles: []string{"viewer"}},
		Action:  "findings.read",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if outcome != PolicyOutcomeNoOpinion {
		t.Fatalf("expected no-opinion, got %q", outcome)
	}
	if reason != "" {
		t.Fatalf("expected empty reason for no-opinion, got %q", reason)
	}
}

func TestABACPolicyEvaluatorAllowWhenActionPolicyMatches(t *testing.T) {
	evaluator := newABACPolicyEvaluator(map[string]abacActionPolicy{
		"findings.triage": {
			AnyOf: []abacClause{
				{
					AllOf: []abacPredicate{
						{
							Source:        abacAttributeSourceSubject,
							Key:           policyAttributeOwnerTeam,
							Operator:      abacOperatorEqualsAttribute,
							CompareSource: abacAttributeSourceResource,
							CompareKey:    policyAttributeOwnerTeam,
						},
						{
							Source:   abacAttributeSourceResource,
							Key:      policyAttributeEnvironment,
							Operator: abacOperatorOneOf,
							Values:   []string{"prod", "staging"},
						},
					},
				},
			},
		},
	})
	outcome, _, err := evaluator.Evaluate(context.Background(), PolicyInput{
		Action: "findings.triage",
		Subject: PolicySubject{
			Attributes: map[string]string{policyAttributeOwnerTeam: "platform"},
		},
		Resource: PolicyResource{
			Attributes: map[string]string{
				policyAttributeOwnerTeam:   "platform",
				policyAttributeEnvironment: "prod",
			},
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if outcome != PolicyOutcomeAllow {
		t.Fatalf("expected allow, got %q", outcome)
	}
}

func TestABACPolicyEvaluatorDenyWhenRequiredAttributeMissing(t *testing.T) {
	evaluator := newABACPolicyEvaluator(map[string]abacActionPolicy{
		"findings.triage": {
			AnyOf: []abacClause{
				{
					AllOf: []abacPredicate{
						{
							Source:        abacAttributeSourceSubject,
							Key:           policyAttributeOwnerTeam,
							Operator:      abacOperatorEqualsAttribute,
							CompareSource: abacAttributeSourceResource,
							CompareKey:    policyAttributeOwnerTeam,
						},
					},
				},
			},
		},
	})
	outcome, reason, err := evaluator.Evaluate(context.Background(), PolicyInput{
		Action: "findings.triage",
		Subject: PolicySubject{
			Attributes: map[string]string{policyAttributeOwnerTeam: "platform"},
		},
		Resource: PolicyResource{},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if outcome != PolicyOutcomeDeny {
		t.Fatalf("expected deny, got %q", outcome)
	}
	if !strings.Contains(reason, "missing resource.owner_team") {
		t.Fatalf("expected missing attribute reason, got %q", reason)
	}
}

func TestABACPolicyEvaluatorNoOpinionWhenActionUnmapped(t *testing.T) {
	evaluator := newABACPolicyEvaluator(map[string]abacActionPolicy{
		"findings.triage": {
			AnyOf: []abacClause{{}},
		},
	})
	outcome, reason, err := evaluator.Evaluate(context.Background(), PolicyInput{
		Action: "scans.read",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if outcome != PolicyOutcomeNoOpinion {
		t.Fatalf("expected no-opinion, got %q", outcome)
	}
	if reason != "" {
		t.Fatalf("expected empty reason, got %q", reason)
	}
}

func TestReBACPolicyEvaluatorAllowWhenDirectRelationshipMatches(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertAuthzRelationship(ctx, db.AuthzRelationship{
		SubjectType: "subject",
		SubjectID:   "principal-1",
		Relation:    db.AuthzRelationshipDelegatedAdmin,
		ObjectType:  "finding",
		ObjectID:    "finding-1",
	}); err != nil {
		t.Fatalf("upsert relationship: %v", err)
	}

	evaluator := newReBACPolicyEvaluator(store, map[string]rebacActionPolicy{
		"findings.triage": {
			AnyOf: []rebacRelationPath{
				{Relations: []string{db.AuthzRelationshipDelegatedAdmin}},
			},
		},
	})

	outcome, reason, err := evaluator.Evaluate(ctx, PolicyInput{
		Action: "findings.triage",
		Subject: PolicySubject{
			Type: "subject",
			ID:   "principal-1",
		},
		Resource: PolicyResource{
			Type: "finding",
			ID:   "finding-1",
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if outcome != PolicyOutcomeAllow {
		t.Fatalf("expected allow, got %q", outcome)
	}
	if strings.TrimSpace(reason) == "" {
		t.Fatal("expected allow reason")
	}
}

func TestReBACPolicyEvaluatorAllowWhenMemberOfPathMatches(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertAuthzRelationship(ctx, db.AuthzRelationship{
		SubjectType: "subject",
		SubjectID:   "principal-1",
		Relation:    db.AuthzRelationshipMemberOf,
		ObjectType:  "team",
		ObjectID:    "platform",
	}); err != nil {
		t.Fatalf("upsert membership relationship: %v", err)
	}
	if err := store.UpsertAuthzRelationship(ctx, db.AuthzRelationship{
		SubjectType: "team",
		SubjectID:   "platform",
		Relation:    db.AuthzRelationshipManages,
		ObjectType:  "finding",
		ObjectID:    "finding-1",
	}); err != nil {
		t.Fatalf("upsert managed relationship: %v", err)
	}

	evaluator := newReBACPolicyEvaluator(store, map[string]rebacActionPolicy{
		"findings.triage": {
			AnyOf: []rebacRelationPath{
				{Relations: []string{db.AuthzRelationshipMemberOf, db.AuthzRelationshipManages}},
			},
		},
	})

	outcome, _, err := evaluator.Evaluate(ctx, PolicyInput{
		Action: "findings.triage",
		Subject: PolicySubject{
			Type: "subject",
			ID:   "principal-1",
		},
		Resource: PolicyResource{
			Type: "finding",
			ID:   "finding-1",
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if outcome != PolicyOutcomeAllow {
		t.Fatalf("expected allow, got %q", outcome)
	}
}

func TestReBACPolicyEvaluatorDenyWhenNoPathMatches(t *testing.T) {
	store := db.NewMemoryStore()
	ctx := db.WithScope(context.Background(), db.Scope{TenantID: "tenant-a", WorkspaceID: "workspace-a"})
	if err := store.UpsertAuthzRelationship(ctx, db.AuthzRelationship{
		SubjectType: "subject",
		SubjectID:   "principal-1",
		Relation:    db.AuthzRelationshipOwns,
		ObjectType:  "finding",
		ObjectID:    "finding-2",
	}); err != nil {
		t.Fatalf("upsert relationship: %v", err)
	}

	evaluator := newReBACPolicyEvaluator(store, map[string]rebacActionPolicy{
		"findings.triage": {
			AnyOf: []rebacRelationPath{
				{Relations: []string{db.AuthzRelationshipOwns}},
			},
		},
	})

	outcome, reason, err := evaluator.Evaluate(ctx, PolicyInput{
		Action: "findings.triage",
		Subject: PolicySubject{
			Type: "subject",
			ID:   "principal-1",
		},
		Resource: PolicyResource{
			Type: "finding",
			ID:   "finding-1",
		},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if outcome != PolicyOutcomeDeny {
		t.Fatalf("expected deny, got %q", outcome)
	}
	if !strings.Contains(reason, "does not grant") {
		t.Fatalf("expected relationship deny reason, got %q", reason)
	}
}
