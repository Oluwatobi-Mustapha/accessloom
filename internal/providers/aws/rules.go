package aws

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

const defaultStaleAfter = 90 * 24 * time.Hour

var adminActions = []string{
	"*",
	"iam:*",
	"sts:*",
	"kms:*",
	"ec2:*",
	"organizations:*",
	"iam:passrole",
	"iam:attachrolepolicy",
	"iam:putrolepolicy",
	"iam:createpolicyversion",
	"sts:assumerole",
}

// RuleOption customizes RuleSet behavior.
type RuleOption func(*RuleSet)

// RuleSet evaluates deterministic risk findings for AWS identities.
type RuleSet struct {
	now        func() time.Time
	staleAfter time.Duration
}

var _ providers.RiskRuleSet = (*RuleSet)(nil)

// NewRuleSet builds the AWS risk rules with safe defaults.
func NewRuleSet(opts ...RuleOption) *RuleSet {
	rules := &RuleSet{
		now:        time.Now,
		staleAfter: defaultStaleAfter,
	}
	for _, opt := range opts {
		opt(rules)
	}
	return rules
}

// WithRuleClock injects deterministic time for tests.
func WithRuleClock(now func() time.Time) RuleOption {
	return func(r *RuleSet) {
		if now != nil {
			r.now = now
		}
	}
}

// WithStaleAfter configures stale identity threshold duration.
func WithStaleAfter(staleAfter time.Duration) RuleOption {
	return func(r *RuleSet) {
		if staleAfter > 0 {
			r.staleAfter = staleAfter
		}
	}
}

type accessRisk struct {
	Action    string
	Resource  string
	NodeID    string
	Escalates bool
}

// Evaluate runs AWS rule checks over normalized identities and relationships.
func (r *RuleSet) Evaluate(ctx context.Context, bundle providers.NormalizedBundle, relationships []domain.Relationship) ([]domain.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	now := r.now().UTC()
	identityByID := make(map[string]domain.Identity, len(bundle.Identities))
	for _, identity := range bundle.Identities {
		identityByID[identity.ID] = identity
	}

	overprivileged := map[string][]accessRisk{}
	riskyTrust := map[string][]string{}

	for _, relationship := range relationships {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		switch relationship.Type {
		case domain.RelationshipCanAccess:
			action, resource, ok := parseAccessNode(relationship.ToNodeID)
			if !ok {
				continue
			}
			if !isOverprivilegedPermission(action, resource) {
				continue
			}
			overprivileged[relationship.FromNodeID] = append(overprivileged[relationship.FromNodeID], accessRisk{
				Action:    action,
				Resource:  resource,
				NodeID:    relationship.ToNodeID,
				Escalates: isEscalationAction(action, resource),
			})
		case domain.RelationshipCanAssume:
			identity, exists := identityByID[relationship.ToNodeID]
			if !exists {
				continue
			}
			targetAccount := accountIDFromARN(identity.ARN)
			if isRiskyPrincipal(relationship.FromNodeID, targetAccount, identityByID) {
				riskyTrust[relationship.ToNodeID] = append(riskyTrust[relationship.ToNodeID], relationship.FromNodeID)
			}
		}
	}

	findings := make([]domain.Finding, 0, len(bundle.Identities)*2)

	for _, identity := range sortedIdentities(bundle.Identities) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if isIdentityOwnerless(identity) {
			findings = append(findings, ownerlessFinding(identity, now))
		}
		if isIdentityStale(identity, now, r.staleAfter) {
			findings = append(findings, staleFinding(identity, now, r.staleAfter))
		}
	}

	for identityID, risks := range overprivileged {
		identity, exists := identityByID[identityID]
		if !exists {
			continue
		}
		findings = append(findings, overprivilegedFinding(identity, risks, now))
	}

	for identityID, principals := range riskyTrust {
		identity, exists := identityByID[identityID]
		if !exists {
			continue
		}
		findings = append(findings, riskyTrustFinding(identity, dedupeStrings(principals), now))
	}

	for identityID, principals := range riskyTrust {
		risks := overprivileged[identityID]
		if len(risks) == 0 {
			continue
		}
		identity, exists := identityByID[identityID]
		if !exists {
			continue
		}
		if !hasEscalationRisk(risks) {
			continue
		}
		findings = append(findings, escalationFinding(identity, dedupeStrings(principals), risks[0], now))
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

func sortedIdentities(identities []domain.Identity) []domain.Identity {
	copied := make([]domain.Identity, len(identities))
	copy(copied, identities)
	sort.Slice(copied, func(i, j int) bool {
		return copied[i].ID < copied[j].ID
	})
	return copied
}

func isIdentityOwnerless(identity domain.Identity) bool {
	return strings.TrimSpace(identity.OwnerHint) == ""
}

func isIdentityStale(identity domain.Identity, now time.Time, staleAfter time.Duration) bool {
	if identity.LastUsedAt != nil {
		return now.Sub(identity.LastUsedAt.UTC()) > staleAfter
	}
	if identity.CreatedAt.IsZero() {
		return false
	}
	return now.Sub(identity.CreatedAt.UTC()) > staleAfter
}

func parseAccessNode(nodeID string) (action string, resource string, ok bool) {
	const prefix = "aws:access:"
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
	if decoded, err := url.QueryUnescape(action); err == nil {
		action = decoded
	}
	if decoded, err := url.QueryUnescape(resource); err == nil {
		resource = decoded
	}
	return action, resource, true
}

func isOverprivilegedPermission(action, resource string) bool {
	a := strings.ToLower(strings.TrimSpace(action))
	r := strings.TrimSpace(resource)
	if a == "*" || strings.HasSuffix(a, ":*") {
		return true
	}
	if r == "*" {
		return true
	}
	return isEscalationAction(action, resource)
}

func isEscalationAction(action, _ string) bool {
	a := strings.ToLower(strings.TrimSpace(action))
	for _, candidate := range adminActions {
		if a == candidate {
			return true
		}
	}
	return false
}

func hasEscalationRisk(risks []accessRisk) bool {
	for _, risk := range risks {
		if risk.Escalates {
			return true
		}
	}
	return false
}

func isRiskyPrincipal(fromNodeID, targetAccount string, identityByID map[string]domain.Identity) bool {
	principal := strings.TrimSpace(fromNodeID)
	if principal == "" {
		return false
	}
	if principal == "aws:principal:*" {
		return true
	}

	if strings.HasPrefix(principal, "aws:identity:") {
		if identity, exists := identityByID[principal]; exists {
			return accountIDFromARN(identity.ARN) != targetAccount
		}
		principal = strings.TrimPrefix(principal, "aws:identity:")
	}
	if strings.HasPrefix(principal, "aws:principal:") {
		principal = strings.TrimPrefix(principal, "aws:principal:")
	}

	if principal == "*" {
		return true
	}
	principalAccount := accountIDFromARN(principal)
	if principalAccount == "" {
		// Unknown principal type is considered risky because blast radius cannot be bounded.
		return true
	}
	if targetAccount == "" {
		return true
	}
	return principalAccount != targetAccount
}

func accountIDFromARN(arn string) string {
	parts := strings.Split(strings.TrimSpace(arn), ":")
	if len(parts) < 6 {
		return ""
	}
	accountID := strings.TrimSpace(parts[4])
	if len(accountID) != 12 {
		return ""
	}
	return accountID
}

func overprivilegedFinding(identity domain.Identity, risks []accessRisk, now time.Time) domain.Finding {
	evidence := make([]map[string]string, 0, len(risks))
	path := make([]string, 0, len(risks)+1)
	path = append(path, identity.ID)
	for _, risk := range risks {
		evidence = append(evidence, map[string]string{
			"action":   risk.Action,
			"resource": risk.Resource,
		})
		path = append(path, risk.NodeID)
	}
	title := fmt.Sprintf("Overprivileged identity: %s", displayIdentity(identity))
	return domain.Finding{
		ID:           findingID(domain.FindingOverPrivileged, identity.ID, fmt.Sprint(len(risks))),
		Type:         domain.FindingOverPrivileged,
		Severity:     domain.SeverityHigh,
		Title:        title,
		HumanSummary: "This identity can perform broad or high-impact actions that materially increase blast radius.",
		Path:         dedupeStrings(path),
		Evidence: map[string]any{
			"identity_id":  identity.ID,
			"identity_arn": identity.ARN,
			"permissions":  evidence,
		},
		Remediation: "Scope permissions to least privilege and remove wildcard or admin-level actions not required by workload behavior.",
		CreatedAt:   now,
	}
}

func riskyTrustFinding(identity domain.Identity, principals []string, now time.Time) domain.Finding {
	title := fmt.Sprintf("Risky trust policy: %s", displayIdentity(identity))
	return domain.Finding{
		ID:           findingID(domain.FindingRiskyTrustPolicy, identity.ID, strings.Join(principals, ",")),
		Type:         domain.FindingRiskyTrustPolicy,
		Severity:     domain.SeverityHigh,
		Title:        title,
		HumanSummary: "This role can be assumed by wildcard or cross-account principals, increasing takeover risk.",
		Path:         append([]string{identity.ID}, principals...),
		Evidence: map[string]any{
			"identity_id":       identity.ID,
			"identity_arn":      identity.ARN,
			"risky_principals":  principals,
			"target_account_id": accountIDFromARN(identity.ARN),
		},
		Remediation: "Restrict trust policy principals to explicitly approved identities and remove wildcard or unnecessary cross-account trust.",
		CreatedAt:   now,
	}
}

func escalationFinding(identity domain.Identity, principals []string, risk accessRisk, now time.Time) domain.Finding {
	principal := "unknown"
	if len(principals) > 0 {
		principal = principals[0]
	}
	title := fmt.Sprintf("Escalation path detected: %s", displayIdentity(identity))
	return domain.Finding{
		ID:           findingID(domain.FindingEscalationPath, identity.ID, principal+"|"+risk.Action),
		Type:         domain.FindingEscalationPath,
		Severity:     domain.SeverityCritical,
		Title:        title,
		HumanSummary: "A risky trust path reaches an identity with high-impact permissions, enabling likely privilege escalation.",
		Path:         []string{principal, identity.ID, risk.NodeID},
		Evidence: map[string]any{
			"identity_id":       identity.ID,
			"identity_arn":      identity.ARN,
			"principal":         principal,
			"escalation_action": risk.Action,
			"resource":          risk.Resource,
		},
		Remediation: "Constrain trust and remove escalation-capable permissions. Require scoped assume-role conditions and least-privilege action/resource constraints.",
		CreatedAt:   now,
	}
}

func staleFinding(identity domain.Identity, now time.Time, staleAfter time.Duration) domain.Finding {
	reference := identity.CreatedAt
	if identity.LastUsedAt != nil {
		reference = identity.LastUsedAt.UTC()
	}
	days := int(staleAfter.Hours() / 24)
	title := fmt.Sprintf("Stale identity: %s", displayIdentity(identity))
	return domain.Finding{
		ID:           findingID(domain.FindingStaleIdentity, identity.ID, reference.Format(time.RFC3339)),
		Type:         domain.FindingStaleIdentity,
		Severity:     domain.SeverityMedium,
		Title:        title,
		HumanSummary: "This identity appears inactive beyond the staleness threshold and should be reviewed or decommissioned.",
		Path:         []string{identity.ID},
		Evidence: map[string]any{
			"identity_id":          identity.ID,
			"identity_arn":         identity.ARN,
			"reference_timestamp":  reference.Format(time.RFC3339),
			"stale_threshold_days": days,
		},
		Remediation: "Validate current workload usage, then disable or remove stale identity permissions if no active dependency exists.",
		CreatedAt:   now,
	}
}

func ownerlessFinding(identity domain.Identity, now time.Time) domain.Finding {
	title := fmt.Sprintf("Ownerless identity: %s", displayIdentity(identity))
	return domain.Finding{
		ID:           findingID(domain.FindingOwnerless, identity.ID, "ownerless"),
		Type:         domain.FindingOwnerless,
		Severity:     domain.SeverityMedium,
		Title:        title,
		HumanSummary: "No ownership signal was detected for this identity, creating response and accountability gaps.",
		Path:         []string{identity.ID},
		Evidence: map[string]any{
			"identity_id":  identity.ID,
			"identity_arn": identity.ARN,
		},
		Remediation: "Assign a clear owner via tags or ownership registry and enforce ownership metadata on new identities.",
		CreatedAt:   now,
	}
}

func findingID(findingType domain.FindingType, identityID, salt string) string {
	raw := string(findingType) + "|" + identityID + "|" + salt
	sum := sha1.Sum([]byte(raw))
	return "aws:finding:" + hex.EncodeToString(sum[:8])
}

func displayIdentity(identity domain.Identity) string {
	if strings.TrimSpace(identity.Name) != "" {
		return identity.Name
	}
	return identity.ARN
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
