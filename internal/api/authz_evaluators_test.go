package api

import (
	"context"
	"strings"
	"testing"
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
