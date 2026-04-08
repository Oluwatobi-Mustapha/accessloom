package api

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type testPolicyEvaluator struct {
	name    string
	outcome PolicyOutcome
	reason  string
	err     error
	calls   *[]string
}

func (e testPolicyEvaluator) Evaluate(_ context.Context, _ PolicyInput) (PolicyOutcome, string, error) {
	if e.calls != nil {
		*e.calls = append(*e.calls, e.name)
	}
	return e.outcome, e.reason, e.err
}

func TestPolicyEngineDecideEnforcesOrderAndDefaultDeny(t *testing.T) {
	calls := []string{}
	engine := NewPolicyEngine(
		testPolicyEvaluator{name: "tenant", outcome: PolicyOutcomeNoOpinion, calls: &calls},
		testPolicyEvaluator{name: "rbac", outcome: PolicyOutcomeNoOpinion, calls: &calls},
		testPolicyEvaluator{name: "abac", outcome: PolicyOutcomeNoOpinion, calls: &calls},
		testPolicyEvaluator{name: "rebac", outcome: PolicyOutcomeNoOpinion, calls: &calls},
	)

	decision, err := engine.Decide(context.Background(), PolicyInput{Action: "findings.read"})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Allowed {
		t.Fatalf("expected default deny decision, got %+v", decision)
	}
	if decision.Stage != PolicyStageDefaultDeny {
		t.Fatalf("expected default deny stage, got %q", decision.Stage)
	}
	expectedCalls := []string{"tenant", "rbac", "abac", "rebac"}
	if !reflect.DeepEqual(calls, expectedCalls) {
		t.Fatalf("expected call order %v, got %v", expectedCalls, calls)
	}
}

func TestPolicyEngineDecideShortCircuitsOnDeny(t *testing.T) {
	calls := []string{}
	engine := NewPolicyEngine(
		testPolicyEvaluator{name: "tenant", outcome: PolicyOutcomeDeny, reason: "tenant mismatch", calls: &calls},
		testPolicyEvaluator{name: "rbac", outcome: PolicyOutcomeAllow, calls: &calls},
		testPolicyEvaluator{name: "abac", outcome: PolicyOutcomeAllow, calls: &calls},
		testPolicyEvaluator{name: "rebac", outcome: PolicyOutcomeAllow, calls: &calls},
	)

	decision, err := engine.Decide(context.Background(), PolicyInput{Action: "findings.read"})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Allowed {
		t.Fatalf("expected deny decision, got %+v", decision)
	}
	if decision.Stage != PolicyStageTenantIsolation {
		t.Fatalf("expected tenant isolation stage, got %q", decision.Stage)
	}
	if decision.Reason != "tenant mismatch" {
		t.Fatalf("expected tenant deny reason, got %q", decision.Reason)
	}
	expectedCalls := []string{"tenant"}
	if !reflect.DeepEqual(calls, expectedCalls) {
		t.Fatalf("expected call order %v, got %v", expectedCalls, calls)
	}
}

func TestPolicyEngineDecideShortCircuitsOnAllow(t *testing.T) {
	calls := []string{}
	engine := NewPolicyEngine(
		testPolicyEvaluator{name: "tenant", outcome: PolicyOutcomeNoOpinion, calls: &calls},
		testPolicyEvaluator{name: "rbac", outcome: PolicyOutcomeAllow, reason: "role grants action", calls: &calls},
		testPolicyEvaluator{name: "abac", outcome: PolicyOutcomeAllow, calls: &calls},
		testPolicyEvaluator{name: "rebac", outcome: PolicyOutcomeAllow, calls: &calls},
	)

	decision, err := engine.Decide(context.Background(), PolicyInput{Action: "findings.read"})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected allow decision, got %+v", decision)
	}
	if decision.Stage != PolicyStageRBAC {
		t.Fatalf("expected rbac stage, got %q", decision.Stage)
	}
	expectedCalls := []string{"tenant", "rbac"}
	if !reflect.DeepEqual(calls, expectedCalls) {
		t.Fatalf("expected call order %v, got %v", expectedCalls, calls)
	}
}

func TestPolicyEngineDecideEvaluatorErrorIncludesStage(t *testing.T) {
	engine := NewPolicyEngine(
		testPolicyEvaluator{name: "tenant", outcome: PolicyOutcomeNoOpinion},
		testPolicyEvaluator{name: "rbac", err: errors.New("db unavailable")},
		nil,
		nil,
	)

	_, err := engine.Decide(context.Background(), PolicyInput{Action: "findings.read"})
	if err == nil {
		t.Fatal("expected evaluator error")
	}
	if !strings.Contains(err.Error(), "rbac") {
		t.Fatalf("expected stage name in error, got %v", err)
	}
}

func TestPolicyEngineDecideRejectsInvalidOutcome(t *testing.T) {
	engine := NewPolicyEngine(
		testPolicyEvaluator{name: "tenant", outcome: PolicyOutcome("maybe")},
		nil,
		nil,
		nil,
	)

	_, err := engine.Decide(context.Background(), PolicyInput{Action: "findings.read"})
	if err == nil {
		t.Fatal("expected invalid outcome error")
	}
	if !strings.Contains(err.Error(), "invalid outcome") {
		t.Fatalf("expected invalid outcome error, got %v", err)
	}
}

func TestPolicyEngineDecideNilEngineDefaultsToDeny(t *testing.T) {
	var engine *PolicyEngine
	decision, err := engine.Decide(context.Background(), PolicyInput{Action: "findings.read"})
	if err != nil {
		t.Fatalf("decide nil engine: %v", err)
	}
	if decision.Allowed {
		t.Fatalf("expected deny decision, got %+v", decision)
	}
	if decision.Stage != PolicyStageDefaultDeny {
		t.Fatalf("expected default deny stage, got %q", decision.Stage)
	}
}
