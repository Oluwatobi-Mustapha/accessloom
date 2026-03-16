package kubernetes

import "strings"

// ObjectMeta captures common Kubernetes metadata.
type ObjectMeta struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels"`
}

// ServiceAccount fixture shape.
type ServiceAccount struct {
	Kind     string     `json:"kind"`
	Metadata ObjectMeta `json:"metadata"`
}

// RoleRef and Subject capture Kubernetes RBAC references.
type RoleRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type Subject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// RoleBinding fixture shape.
type RoleBinding struct {
	Kind     string     `json:"kind"`
	Metadata ObjectMeta `json:"metadata"`
	RoleRef  RoleRef    `json:"roleRef"`
	Subjects []Subject  `json:"subjects"`
}

// Pod fixture shape.
type Pod struct {
	Kind     string     `json:"kind"`
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		ServiceAccountName string `json:"serviceAccountName"`
	} `json:"spec"`
}

func serviceAccountID(namespace, name string) string {
	return "k8s:identity:sa:" + strings.TrimSpace(namespace) + ":" + strings.TrimSpace(name)
}

func workloadID(namespace, name string) string {
	return "k8s:workload:pod:" + strings.TrimSpace(namespace) + ":" + strings.TrimSpace(name)
}

func policyID(scope, name, identityID string) string {
	return "k8s:policy:" + strings.ToLower(strings.TrimSpace(scope)) + ":" + strings.TrimSpace(name) + ":" + strings.TrimSpace(identityID)
}

func accessNodeID(action, resource string) string {
	return "k8s:access:" + strings.TrimSpace(action) + ":" + strings.TrimSpace(resource)
}

func ownerHint(labels map[string]string) string {
	for _, key := range []string{"owner", "team", "service"} {
		if value := strings.TrimSpace(labels[key]); value != "" {
			return value
		}
	}
	return ""
}

func copyLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	copied := make(map[string]string, len(labels))
	for key, value := range labels {
		copied[key] = value
	}
	return copied
}
