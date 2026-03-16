package aws

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
)

func loadRawRoleAssetFixture(t *testing.T, fileName string) providers.RawAsset {
	t.Helper()
	path := filepath.Join("..", "..", "..", "testdata", "aws", fileName)
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}

	var role IAMRole
	if err := json.Unmarshal(payload, &role); err != nil {
		t.Fatalf("decode fixture %s: %v", path, err)
	}

	return providers.RawAsset{
		Kind:     "iam_role",
		SourceID: role.ARN,
		Payload:  payload,
	}
}

func findPolicyByType(t *testing.T, policies []map[string]any, expectedType string) map[string]any {
	t.Helper()
	for _, policy := range policies {
		if policy[policyTypeKey] == expectedType {
			return policy
		}
	}
	t.Fatalf("policy type %q not found", expectedType)
	return nil
}
