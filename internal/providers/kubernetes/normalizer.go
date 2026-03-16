package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

const (
	policyTypeKey  = "policy_type"
	policyTypePerm = "permission"
	identityIDKey  = "identity_id"
	statementsKey  = "statements"
)

// Normalizer transforms Kubernetes raw assets into normalized entities.
type Normalizer struct{}

var _ providers.Normalizer = (*Normalizer)(nil)

// NewNormalizer returns the Kubernetes normalizer.
func NewNormalizer() *Normalizer { return &Normalizer{} }

// Normalize converts raw Kubernetes assets to identities/workloads/policies.
func (n *Normalizer) Normalize(ctx context.Context, raw []providers.RawAsset) (providers.NormalizedBundle, error) {
	bundle := providers.NormalizedBundle{}
	identitySeen := map[string]struct{}{}
	policySeen := map[string]struct{}{}
	for i, asset := range raw {
		if err := ctx.Err(); err != nil {
			return providers.NormalizedBundle{}, err
		}
		switch asset.Kind {
		case "k8s_service_account":
			var sa ServiceAccount
			if err := json.Unmarshal(asset.Payload, &sa); err != nil {
				return providers.NormalizedBundle{}, fmt.Errorf("decode service account asset[%d]: %w", i, err)
			}
			ns := strings.TrimSpace(sa.Metadata.Namespace)
			name := strings.TrimSpace(sa.Metadata.Name)
			if ns == "" || name == "" {
				continue
			}
			identityID := serviceAccountID(ns, name)
			if _, exists := identitySeen[identityID]; exists {
				continue
			}
			identitySeen[identityID] = struct{}{}
			bundle.Identities = append(bundle.Identities, domain.Identity{
				ID:        identityID,
				Provider:  domain.ProviderKubernetes,
				Type:      domain.IdentityTypeServiceAccount,
				Name:      ns + "/" + name,
				ARN:       identityID,
				OwnerHint: ownerHint(sa.Metadata.Labels),
				Tags:      copyLabels(sa.Metadata.Labels),
				RawRef:    asset.SourceID,
			})
		case "k8s_pod":
			var pod Pod
			if err := json.Unmarshal(asset.Payload, &pod); err != nil {
				return providers.NormalizedBundle{}, fmt.Errorf("decode pod asset[%d]: %w", i, err)
			}
			ns := strings.TrimSpace(pod.Metadata.Namespace)
			name := strings.TrimSpace(pod.Metadata.Name)
			saName := strings.TrimSpace(pod.Spec.ServiceAccountName)
			if ns == "" || name == "" {
				continue
			}
			if saName == "" {
				saName = "default"
			}
			bundle.Workloads = append(bundle.Workloads, domain.Workload{
				ID:        workloadID(ns, name),
				Provider:  domain.ProviderKubernetes,
				Type:      "pod",
				Name:      ns + "/" + name,
				AccountID: ns,
				Region:    "cluster-local",
				RawRef:    serviceAccountID(ns, saName),
			})
		case "k8s_role_binding":
			var binding RoleBinding
			if err := json.Unmarshal(asset.Payload, &binding); err != nil {
				return providers.NormalizedBundle{}, fmt.Errorf("decode role binding asset[%d]: %w", i, err)
			}
			bindingName := strings.TrimSpace(binding.Metadata.Name)
			if bindingName == "" {
				continue
			}
			statements := statementsForRole(binding.RoleRef.Name)
			if len(statements) == 0 {
				continue
			}
			scope := strings.TrimSpace(binding.Metadata.Namespace)
			if scope == "" {
				scope = "cluster"
			}
			for _, subject := range binding.Subjects {
				if !strings.EqualFold(strings.TrimSpace(subject.Kind), "ServiceAccount") {
					continue
				}
				ns := strings.TrimSpace(subject.Namespace)
				if ns == "" {
					ns = strings.TrimSpace(binding.Metadata.Namespace)
				}
				name := strings.TrimSpace(subject.Name)
				if ns == "" || name == "" {
					continue
				}
				identityID := serviceAccountID(ns, name)
				id := policyID(scope, bindingName, identityID)
				if _, exists := policySeen[id]; exists {
					continue
				}
				policySeen[id] = struct{}{}
				bundle.Policies = append(bundle.Policies, domain.Policy{
					ID:       id,
					Provider: domain.ProviderKubernetes,
					Name:     bindingName,
					Document: asset.Payload,
					Normalized: map[string]any{
						policyTypeKey: policyTypePerm,
						identityIDKey: identityID,
						statementsKey: statements,
					},
					RawRef: asset.SourceID,
				})
			}
		}
	}
	return bundle, nil
}

func statementsForRole(roleName string) []map[string]any {
	normalized := strings.ToLower(strings.TrimSpace(roleName))
	switch normalized {
	case "cluster-admin", "admin":
		return []map[string]any{{"effect": "Allow", "actions": []string{"*"}, "resources": []string{"*"}}}
	case "view", "read", "reader":
		return []map[string]any{{"effect": "Allow", "actions": []string{"get", "list", "watch"}, "resources": []string{"*"}}}
	case "edit":
		return []map[string]any{{"effect": "Allow", "actions": []string{"get", "list", "watch", "create", "update", "patch"}, "resources": []string{"*"}}}
	default:
		return nil
	}
}
