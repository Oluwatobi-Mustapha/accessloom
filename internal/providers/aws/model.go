package aws

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// IAMPermissionPolicy stores an identity permission policy with provider-native JSON.
type IAMPermissionPolicy struct {
	Name     string `json:"name"`
	Document string `json:"document"`
}

// iamPolicyDocument models the subset of IAM policy grammar used in phase 1.
type iamPolicyDocument struct {
	Version   string              `json:"Version"`
	Statement iamPolicyStatements `json:"Statement"`
}

type iamPolicyStatements []iamPolicyStatement

type iamPolicyStatement struct {
	Effect    string `json:"Effect"`
	Action    any    `json:"Action,omitempty"`
	Resource  any    `json:"Resource,omitempty"`
	Principal any    `json:"Principal,omitempty"`
}

func (s *iamPolicyStatements) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		*s = nil
		return nil
	}

	var single iamPolicyStatement
	if err := json.Unmarshal(data, &single); err == nil && single.Effect != "" {
		*s = []iamPolicyStatement{single}
		return nil
	}

	var many []iamPolicyStatement
	if err := json.Unmarshal(data, &many); err == nil {
		*s = many
		return nil
	}

	return fmt.Errorf("invalid policy statement shape")
}

func parsePolicyDocument(raw string) (iamPolicyDocument, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return iamPolicyDocument{}, nil
	}

	decoded := trimmed
	if strings.Contains(trimmed, "%") {
		if unescaped, err := url.QueryUnescape(trimmed); err == nil {
			decoded = unescaped
		}
	}

	var doc iamPolicyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return iamPolicyDocument{}, fmt.Errorf("parse policy document: %w", err)
	}
	return doc, nil
}

func normalizedStatement(effect string, actions, resources []string) map[string]any {
	return map[string]any{
		"effect":    canonicalEffect(effect),
		"actions":   dedupeStrings(actions),
		"resources": dedupeStrings(resources),
	}
}

func canonicalEffect(effect string) string {
	if strings.EqualFold(effect, "deny") {
		return "Deny"
	}
	return "Allow"
}

func dedupeStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	result := make([]string, 0, len(items))
	for _, item := range items {
		normalized := strings.TrimSpace(item)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result
}

func parseStringList(value any) []string {
	switch typed := value.(type) {
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return []string{typed}
	case []any:
		values := make([]string, 0, len(typed))
		for _, entry := range typed {
			if s, ok := entry.(string); ok && strings.TrimSpace(s) != "" {
				values = append(values, s)
			}
		}
		return values
	case []string:
		return typed
	default:
		return nil
	}
}

func parseAWSPrincipals(principal any) []string {
	if principal == nil {
		return nil
	}

	if star, ok := principal.(string); ok {
		if star == "*" {
			return []string{"*"}
		}
		return nil
	}

	principalMap, ok := principal.(map[string]any)
	if !ok {
		return nil
	}

	values, ok := principalMap["AWS"]
	if !ok {
		return nil
	}
	return dedupeStrings(parseStringList(values))
}
