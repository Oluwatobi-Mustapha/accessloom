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
		APIKeyScopes: map[string][]string{"writer": []string{"write"}},
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

func TestSecurityWarnings(t *testing.T) {
	cfg := Config{
		AlertWebhookURL: "https://alerts.example.com/hook",
	}
	warnings := SecurityWarnings(cfg)
	if len(warnings) < 3 {
		t.Fatalf("expected multiple warnings, got %+v", warnings)
	}
}
