package api

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// PolicyStage identifies one authorization layer in the centralized decision pipeline.
type PolicyStage string

const (
	PolicyStageTenantIsolation PolicyStage = "tenant_isolation"
	PolicyStageRBAC            PolicyStage = "rbac"
	PolicyStageABAC            PolicyStage = "abac"
	PolicyStageReBAC           PolicyStage = "rebac"
	PolicyStageDefaultDeny     PolicyStage = "default_deny"
)

// PolicyOutcome captures one evaluator result.
type PolicyOutcome string

const (
	PolicyOutcomeNoOpinion PolicyOutcome = "no_op"
	PolicyOutcomeAllow     PolicyOutcome = "allow"
	PolicyOutcomeDeny      PolicyOutcome = "deny"
)

// PolicySubject is the actor for one authorization decision.
type PolicySubject struct {
	Type        string
	ID          string
	TenantID    string
	WorkspaceID string
	Groups      []string
	Roles       []string
	Attributes  map[string]string
}

// PolicyResource identifies the target object.
type PolicyResource struct {
	Type        string
	ID          string
	TenantID    string
	WorkspaceID string
	Attributes  map[string]string
}

// PolicyContext captures request-time facts used in policy evaluation.
type PolicyContext struct {
	RequestPath   string
	RequestMethod string
	Now           time.Time
	Attributes    map[string]string
}

// PolicyInput is the single input model for centralized authorization.
type PolicyInput struct {
	Subject  PolicySubject
	Action   string
	Resource PolicyResource
	Context  PolicyContext
}

// PolicyDecision is the normalized authorization outcome.
type PolicyDecision struct {
	Allowed bool
	Stage   PolicyStage
	Reason  string
}

// PolicyEvaluator evaluates one authorization layer.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, input PolicyInput) (PolicyOutcome, string, error)
}

// PolicyEngine evaluates authorization in strict order:
// tenant isolation -> RBAC -> ABAC -> ReBAC -> default deny.
type PolicyEngine struct {
	TenantIsolationEvaluator PolicyEvaluator
	RBACEvaluator            PolicyEvaluator
	ABACEvaluator            PolicyEvaluator
	ReBACEvaluator           PolicyEvaluator
}

// NewPolicyEngine creates one centralized authorization engine.
func NewPolicyEngine(tenantIsolation PolicyEvaluator, rbac PolicyEvaluator, abac PolicyEvaluator, rebac PolicyEvaluator) *PolicyEngine {
	return &PolicyEngine{
		TenantIsolationEvaluator: tenantIsolation,
		RBACEvaluator:            rbac,
		ABACEvaluator:            abac,
		ReBACEvaluator:           rebac,
	}
}

// Decide evaluates authorization policies and returns one normalized decision.
func (p *PolicyEngine) Decide(ctx context.Context, input PolicyInput) (PolicyDecision, error) {
	if p == nil {
		return denyDecision(PolicyStageDefaultDeny, "authorization policy engine is not configured"), nil
	}
	for _, stage := range []struct {
		name      PolicyStage
		evaluator PolicyEvaluator
	}{
		{name: PolicyStageTenantIsolation, evaluator: p.TenantIsolationEvaluator},
		{name: PolicyStageRBAC, evaluator: p.RBACEvaluator},
		{name: PolicyStageABAC, evaluator: p.ABACEvaluator},
		{name: PolicyStageReBAC, evaluator: p.ReBACEvaluator},
	} {
		if stage.evaluator == nil {
			continue
		}
		outcome, reason, err := stage.evaluator.Evaluate(ctx, input)
		if err != nil {
			return PolicyDecision{}, fmt.Errorf("evaluate %s policy: %w", stage.name, err)
		}
		reason = strings.TrimSpace(reason)
		switch outcome {
		case PolicyOutcomeAllow:
			return PolicyDecision{Allowed: true, Stage: stage.name, Reason: reason}, nil
		case PolicyOutcomeDeny:
			return denyDecision(stage.name, reason), nil
		case PolicyOutcomeNoOpinion:
			continue
		default:
			return PolicyDecision{}, fmt.Errorf("evaluate %s policy: invalid outcome %q", stage.name, outcome)
		}
	}
	return denyDecision(PolicyStageDefaultDeny, "no policy granted access"), nil
}

func denyDecision(stage PolicyStage, reason string) PolicyDecision {
	message := strings.TrimSpace(reason)
	if message == "" {
		message = "access denied"
	}
	return PolicyDecision{Allowed: false, Stage: stage, Reason: message}
}
