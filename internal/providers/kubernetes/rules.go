package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

// RuleSet evaluates deterministic Kubernetes identity risks.
type RuleSet struct {
	now func() time.Time
}

var _ providers.RiskRuleSet = (*RuleSet)(nil)

// NewRuleSet creates a Kubernetes rule set with safe deterministic defaults.
func NewRuleSet() *RuleSet {
	return &RuleSet{now: time.Now}
}

// Evaluate detects broad permissions, privilege escalation paths, and missing ownership.
func (r *RuleSet) Evaluate(ctx context.Context, bundle providers.NormalizedBundle, relationships []domain.Relationship) ([]domain.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	now := r.now().UTC()
	identityByID := make(map[string]domain.Identity, len(bundle.Identities))
	for _, identity := range bundle.Identities {
		identityByID[identity.ID] = identity
	}

	identityWorkloads := map[string][]string{}
	identityRisks := map[string][]accessRisk{}

	for _, relationship := range relationships {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		switch relationship.Type {
		case domain.RelationshipBoundTo:
			identityWorkloads[relationship.ToNodeID] = append(identityWorkloads[relationship.ToNodeID], relationship.FromNodeID)
		case domain.RelationshipCanAccess:
			action, resource, ok := parseAccessNode(relationship.ToNodeID)
			if !ok {
				continue
			}
			if !isOverprivilegedPermission(action, resource) {
				continue
			}
			identityRisks[relationship.FromNodeID] = append(identityRisks[relationship.FromNodeID], accessRisk{
				Action:    action,
				Resource:  resource,
				NodeID:    relationship.ToNodeID,
				Escalates: isEscalationPermission(action, resource),
			})
		}
	}

	findings := make([]domain.Finding, 0, len(bundle.Identities)*2)
	for _, identity := range sortedIdentities(bundle.Identities) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if strings.TrimSpace(identity.OwnerHint) == "" {
			findings = append(findings, ownerlessFinding(identity, now))
		}
		risks := identityRisks[identity.ID]
		if len(risks) == 0 {
			continue
		}
		sortedRisks := sortAccessRisks(risks)
		findings = append(findings, overprivilegedFinding(identity, sortedRisks, now))
		if !hasEscalationRisk(risks) {
			continue
		}
		for _, workloadID := range dedupeStrings(identityWorkloads[identity.ID]) {
			findings = append(findings, escalationFinding(identity, workloadID, sortedRisks, now))
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity == findings[j].Severity {
			if findings[i].Type == findings[j].Type {
				return findings[i].ID < findings[j].ID
			}
			return findings[i].Type < findings[j].Type
		}
		return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
	})

	return findings, nil
}

type accessRisk struct {
	Action    string
	Resource  string
	NodeID    string
	Escalates bool
}

func parseAccessNode(nodeID string) (action string, resource string, ok bool) {
	const prefix = "k8s:access:"
	if !strings.HasPrefix(nodeID, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(nodeID, prefix)
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	action = strings.TrimSpace(parts[0])
	resource = strings.TrimSpace(parts[1])
	if action == "" || resource == "" {
		return "", "", false
	}
	return action, resource, true
}

func isOverprivilegedPermission(action, resource string) bool {
	a := strings.ToLower(strings.TrimSpace(action))
	r := strings.ToLower(strings.TrimSpace(resource))
	if a == "*" || r == "*" {
		return true
	}
	if strings.HasSuffix(a, "*") {
		return true
	}
	return isEscalationPermission(action, resource)
}

func isEscalationPermission(action, resource string) bool {
	a := strings.ToLower(strings.TrimSpace(action))
	r := strings.ToLower(strings.TrimSpace(resource))
	if a == "*" {
		return true
	}
	if r == "*" && (a == "create" || a == "update" || a == "patch" || a == "delete" || a == "escalate" || a == "bind" || a == "impersonate") {
		return true
	}
	switch r {
	case "clusterrolebindings", "rolebindings", "clusterroles", "roles", "secrets":
		return a == "create" || a == "update" || a == "patch" || a == "delete" || a == "escalate" || a == "bind" || a == "impersonate"
	default:
		return false
	}
}

func hasEscalationRisk(risks []accessRisk) bool {
	for _, risk := range risks {
		if risk.Escalates {
			return true
		}
	}
	return false
}

func sortAccessRisks(risks []accessRisk) []accessRisk {
	if len(risks) == 0 {
		return nil
	}
	sorted := make([]accessRisk, len(risks))
	copy(sorted, risks)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Escalates != sorted[j].Escalates {
			return sorted[i].Escalates
		}
		if sorted[i].Action != sorted[j].Action {
			return sorted[i].Action < sorted[j].Action
		}
		if sorted[i].Resource != sorted[j].Resource {
			return sorted[i].Resource < sorted[j].Resource
		}
		return sorted[i].NodeID < sorted[j].NodeID
	})
	return sorted
}

func sortedIdentities(identities []domain.Identity) []domain.Identity {
	copied := make([]domain.Identity, len(identities))
	copy(copied, identities)
	sort.Slice(copied, func(i, j int) bool {
		return copied[i].ID < copied[j].ID
	})
	return copied
}

func ownerlessFinding(identity domain.Identity, now time.Time) domain.Finding {
	return domain.Finding{
		ID:           findingID(string(domain.FindingOwnerless), identity.ID, "ownerless"),
		Type:         domain.FindingOwnerless,
		Severity:     domain.SeverityMedium,
		Title:        fmt.Sprintf("Service account %s has no owner metadata", identity.Name),
		HumanSummary: "This service account is missing owner labels, making incident response and remediation slower.",
		Path:         []string{identity.ID},
		Evidence: map[string]any{
			"identity_id": identity.ID,
			"provider":    identity.Provider,
		},
		Remediation: "Add `owner` or `team` labels to the service account and enforce owner-label policy in CI.",
		CreatedAt:   now,
	}
}

func overprivilegedFinding(identity domain.Identity, risks []accessRisk, now time.Time) domain.Finding {
	top := risks[0]
	return domain.Finding{
		ID:           findingID(string(domain.FindingOverPrivileged), identity.ID, top.NodeID),
		Type:         domain.FindingOverPrivileged,
		Severity:     domain.SeverityHigh,
		Title:        fmt.Sprintf("Service account %s is broadly privileged", identity.Name),
		HumanSummary: "This service account can perform broad actions that expand blast radius across the cluster.",
		Path:         []string{identity.ID, top.NodeID},
		Evidence: map[string]any{
			"identity_id": identity.ID,
			"risk_count":  len(risks),
			"sample": map[string]any{
				"action":   top.Action,
				"resource": top.Resource,
			},
		},
		Remediation: "Replace broad ClusterRole/Role bindings with least-privilege roles scoped to required namespaces and verbs.",
		CreatedAt:   now,
	}
}

func escalationFinding(identity domain.Identity, workloadID string, risks []accessRisk, now time.Time) domain.Finding {
	criticalRisk := risks[0]
	for _, risk := range risks {
		if risk.Escalates {
			criticalRisk = risk
			break
		}
	}
	return domain.Finding{
		ID:           findingID(string(domain.FindingEscalationPath), identity.ID, workloadID, criticalRisk.NodeID),
		Type:         domain.FindingEscalationPath,
		Severity:     domain.SeverityCritical,
		Title:        fmt.Sprintf("Workload %s can escalate via %s", workloadID, identity.Name),
		HumanSummary: "A workload is bound to a highly privileged service account with escalation-capable permissions.",
		Path:         []string{workloadID, identity.ID, criticalRisk.NodeID},
		Evidence: map[string]any{
			"workload_id": workloadID,
			"identity_id": identity.ID,
			"action":      criticalRisk.Action,
			"resource":    criticalRisk.Resource,
		},
		Remediation: "Use dedicated service accounts per workload and remove escalation verbs (`bind`, `escalate`, wildcard permissions).",
		CreatedAt:   now,
	}
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func severityRank(severity domain.FindingSeverity) int {
	switch severity {
	case domain.SeverityCritical:
		return 0
	case domain.SeverityHigh:
		return 1
	case domain.SeverityMedium:
		return 2
	case domain.SeverityLow:
		return 3
	default:
		return 4
	}
}

func findingID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return "k8s:finding:" + hex.EncodeToString(sum[:])
}
