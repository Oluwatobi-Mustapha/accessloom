package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
)

// UpsertRBACRole creates or updates a workspace-scoped RBAC role.
func (s *Service) UpsertRBACRole(ctx context.Context, role db.RBACRole) (db.RBACRole, error) {
	ctx = s.scopeContext(ctx)
	name := strings.ToLower(strings.TrimSpace(role.Name))
	if name == "" {
		return db.RBACRole{}, fmt.Errorf("role name is required")
	}
	role.Name = name
	role.Description = strings.TrimSpace(role.Description)
	role.Permissions = normalizePermissionList(role.Permissions)
	if len(role.Permissions) == 0 {
		return db.RBACRole{}, fmt.Errorf("role permissions are required")
	}
	return s.Store.UpsertRBACRole(ctx, role)
}

// ListRBACRoles returns role definitions for current workspace scope.
func (s *Service) ListRBACRoles(ctx context.Context) ([]db.RBACRole, error) {
	ctx = s.scopeContext(ctx)
	roles, err := s.Store.ListRBACRoles(ctx)
	if err != nil {
		return nil, err
	}
	for i := range roles {
		roles[i].Permissions = normalizePermissionList(roles[i].Permissions)
	}
	return roles, nil
}

// DeleteRBACRole removes a custom role in the current workspace.
func (s *Service) DeleteRBACRole(ctx context.Context, roleID string) error {
	ctx = s.scopeContext(ctx)
	return s.Store.DeleteRBACRole(ctx, strings.TrimSpace(roleID))
}

// UpsertRBACBinding creates or updates a subject-role binding.
func (s *Service) UpsertRBACBinding(ctx context.Context, binding db.RBACBinding) (db.RBACBinding, error) {
	ctx = s.scopeContext(ctx)
	binding.SubjectType = strings.ToLower(strings.TrimSpace(binding.SubjectType))
	binding.SubjectID = strings.TrimSpace(binding.SubjectID)
	binding.RoleID = strings.TrimSpace(binding.RoleID)
	if binding.SubjectID == "" || binding.RoleID == "" {
		return db.RBACBinding{}, fmt.Errorf("subject_id and role_id are required")
	}
	if binding.ExpiresAt != nil {
		expires := binding.ExpiresAt.UTC()
		binding.ExpiresAt = &expires
	}
	return s.Store.UpsertRBACBinding(ctx, binding)
}

// ListRBACBindings returns current workspace bindings.
func (s *Service) ListRBACBindings(ctx context.Context) ([]db.RBACBinding, error) {
	ctx = s.scopeContext(ctx)
	return s.Store.ListRBACBindings(ctx)
}

// DeleteRBACBinding removes one binding in current scope.
func (s *Service) DeleteRBACBinding(ctx context.Context, bindingID string) error {
	ctx = s.scopeContext(ctx)
	return s.Store.DeleteRBACBinding(ctx, strings.TrimSpace(bindingID))
}

func normalizePermissionList(values []string) []string {
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
	return permissions
}

func parseOptionalRFC3339(raw string) (*time.Time, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp format")
	}
	value := parsed.UTC()
	return &value, nil
}
