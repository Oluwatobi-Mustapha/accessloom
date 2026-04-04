package db

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	// RBACSubjectTypeOIDCSubject binds permissions to a verified OIDC subject (sub claim).
	RBACSubjectTypeOIDCSubject = "oidc_subject"
	// RBACSubjectTypeAPIKey binds permissions to an API key fingerprint.
	RBACSubjectTypeAPIKey = "api_key"
)

// RBACRole defines one workspace-scoped role and its permissions.
type RBACRole struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"-"`
	WorkspaceID string    `json:"-"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	IsBuiltIn   bool      `json:"is_builtin"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RBACBinding links one subject to one role inside one tenant/workspace scope.
type RBACBinding struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"-"`
	WorkspaceID string     `json:"-"`
	SubjectType string     `json:"subject_type"`
	SubjectID   string     `json:"subject_id"`
	RoleID      string     `json:"role_id"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

func normalizeRBACSubjectType(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case RBACSubjectTypeOIDCSubject, RBACSubjectTypeAPIKey:
		return normalized, nil
	default:
		return "", fmt.Errorf("invalid rbac subject type")
	}
}

func normalizeRBACPermissionList(values []string) []string {
	seen := map[string]struct{}{}
	permissions := make([]string, 0, len(values))
	for _, item := range values {
		normalized := strings.ToLower(strings.TrimSpace(item))
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		permissions = append(permissions, normalized)
	}
	sort.Strings(permissions)
	return permissions
}
