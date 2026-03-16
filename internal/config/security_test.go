package config

import "testing"

func TestValidateSecurityWriteKeyMustBeInAPIKeys(t *testing.T) {
	cfg := Config{
		APIKeys:      []string{"reader"},
		WriteAPIKeys: []string{"writer"},
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateSecurityWriteKeyCheckSkippedWhenScopedKeysPresent(t *testing.T) {
	cfg := Config{
		WriteAPIKeys: []string{"writer"},
		APIKeyScopes: map[string][]string{"writer": {"write"}},
	}
	if err := ValidateSecurity(cfg); err != nil {
		t.Fatalf("expected validation success, got %v", err)
	}
}

func TestValidateSecuritySuccess(t *testing.T) {
	cfg := Config{
		APIKeys:      []string{"reader", "writer"},
		WriteAPIKeys: []string{"writer"},
	}
	if err := ValidateSecurity(cfg); err != nil {
		t.Fatalf("expected validation success, got %v", err)
	}
}

func TestValidateSecurityRejectsInvalidScopedKeyScope(t *testing.T) {
	cfg := Config{
		APIKeyScopes: map[string][]string{"key1": {"invalid"}},
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected invalid scope error")
	}
}

func TestValidateSecurityRejectsScopedKeyWithoutValidScope(t *testing.T) {
	cfg := Config{
		APIKeyScopes: map[string][]string{"key1": {""}},
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected empty scope error")
	}
}

func TestValidateSecurityRejectsLargeAlertMaxFindings(t *testing.T) {
	cfg := Config{
		AlertMaxFindings: maxAlertFindingsLimit + 1,
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected alert max findings validation error")
	}
}

func TestValidateSecurityRejectsInvalidAlertSeverity(t *testing.T) {
	cfg := Config{
		AlertWebhookURL:  "https://alerts.example.com/hook",
		AlertMinSeverity: "extreme",
	}
	if err := ValidateSecurity(cfg); err == nil {
		t.Fatal("expected alert severity validation error")
	}
}

func TestSecurityWarnings(t *testing.T) {
	cfg := Config{
		APIKeys:         []string{"legacy-key"},
		APIKeyScopes:    map[string][]string{"reader-key": {"read"}},
		AlertWebhookURL: "https://alerts.example.com/hook",
	}
	warnings := SecurityWarnings(cfg)
	if len(warnings) < 3 {
		t.Fatalf("expected multiple warnings, got %+v", warnings)
	}
}
