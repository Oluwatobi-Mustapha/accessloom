package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeRawTokenVerifier struct {
	token tokenClaimsDecoder
	err   error
}

func (f fakeRawTokenVerifier) Verify(context.Context, string) (tokenClaimsDecoder, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.token, nil
}

type fakeClaimsDecoder struct {
	claims map[string]any
	err    error
}

func (d fakeClaimsDecoder) Claims(v interface{}) error {
	if d.err != nil {
		return d.err
	}
	payload, err := json.Marshal(d.claims)
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, v)
}

func TestNewOIDCTokenVerifierValidation(t *testing.T) {
	if _, err := NewOIDCTokenVerifier(context.Background(), "", "aud", "tenant_id", "workspace_id", "groups", "roles"); err == nil {
		t.Fatal("expected missing issuer validation error")
	}
	if _, err := NewOIDCTokenVerifier(context.Background(), "https://issuer.example.com", "", "tenant_id", "workspace_id", "groups", "roles"); err == nil {
		t.Fatal("expected missing audience validation error")
	}
}

func TestNewOIDCTokenVerifierDiscoveryFailure(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	if _, err := NewOIDCTokenVerifier(context.Background(), srv.URL, "identrail", "tenant_id", "workspace_id", "groups", "roles"); err == nil {
		t.Fatal("expected discovery failure")
	}
}

func TestOIDCTokenVerifierVerifyToken(t *testing.T) {
	verifier := &OIDCTokenVerifier{
		expectedIssuer: "https://issuer.example.com",
		expectedAud:    "identrail-api",
		tenantClaim:    "tenant_id",
		workspaceClaim: "workspace_id",
		groupsClaim:    "groups",
		rolesClaim:     "roles",
		verifier: fakeRawTokenVerifier{
			token: fakeClaimsDecoder{
				claims: map[string]any{
					"sub":          "subject-1",
					"iss":          "https://issuer.example.com",
					"aud":          []string{"identrail-api", "other"},
					"tenant_id":    "tenant-1",
					"workspace_id": "workspace-1",
					"groups":       []string{"engineering"},
					"roles":        []string{"admin"},
					"scope":        "read write",
					"scp":          []string{"identrail.admin"},
				},
			},
		},
	}

	token, err := verifier.VerifyToken(context.Background(), "token")
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if token.Subject != "subject-1" {
		t.Fatalf("unexpected subject %q", token.Subject)
	}
	if token.TenantID != "tenant-1" {
		t.Fatalf("unexpected tenant %q", token.TenantID)
	}
	if token.WorkspaceID != "workspace-1" {
		t.Fatalf("unexpected workspace %q", token.WorkspaceID)
	}
	if len(token.Groups) != 1 || token.Groups[0] != "engineering" {
		t.Fatalf("unexpected groups %+v", token.Groups)
	}
	if len(token.Roles) != 1 || token.Roles[0] != "admin" {
		t.Fatalf("unexpected roles %+v", token.Roles)
	}
	if len(token.Scopes) != 3 {
		t.Fatalf("expected 3 scopes, got %+v", token.Scopes)
	}
}

func TestOIDCTokenVerifierVerifyTokenErrors(t *testing.T) {
	if _, err := (&OIDCTokenVerifier{}).VerifyToken(context.Background(), "token"); err == nil {
		t.Fatal("expected nil verifier error")
	}

	verifierErr := &OIDCTokenVerifier{
		verifier: fakeRawTokenVerifier{err: errors.New("invalid token")},
	}
	if _, err := verifierErr.VerifyToken(context.Background(), "token"); err == nil {
		t.Fatal("expected verify error")
	}

	claimsErr := &OIDCTokenVerifier{
		verifier: fakeRawTokenVerifier{
			token: fakeClaimsDecoder{err: errors.New("bad claims")},
		},
	}
	if _, err := claimsErr.VerifyToken(context.Background(), "token"); err == nil {
		t.Fatal("expected claims decode error")
	}
}

func TestOIDCTokenVerifierStrictClaimValidation(t *testing.T) {
	baseClaims := map[string]any{
		"sub":          "subject-1",
		"iss":          "https://issuer.example.com",
		"aud":          "identrail-api",
		"tenant_id":    "tenant-1",
		"workspace_id": "workspace-1",
		"groups":       []string{"engineering"},
		"roles":        []string{"viewer"},
		"scope":        "read",
	}

	testCases := []struct {
		name   string
		claims map[string]any
	}{
		{
			name: "missing sub",
			claims: map[string]any{
				"iss":          "https://issuer.example.com",
				"aud":          "identrail-api",
				"tenant_id":    "tenant-1",
				"workspace_id": "workspace-1",
			},
		},
		{
			name: "issuer mismatch",
			claims: map[string]any{
				"sub":          "subject-1",
				"iss":          "https://other-issuer.example.com",
				"aud":          "identrail-api",
				"tenant_id":    "tenant-1",
				"workspace_id": "workspace-1",
			},
		},
		{
			name: "audience mismatch",
			claims: map[string]any{
				"sub":          "subject-1",
				"iss":          "https://issuer.example.com",
				"aud":          "other-aud",
				"tenant_id":    "tenant-1",
				"workspace_id": "workspace-1",
			},
		},
		{
			name: "missing tenant claim",
			claims: map[string]any{
				"sub":          "subject-1",
				"iss":          "https://issuer.example.com",
				"aud":          "identrail-api",
				"workspace_id": "workspace-1",
			},
		},
		{
			name: "missing workspace claim",
			claims: map[string]any{
				"sub":       "subject-1",
				"iss":       "https://issuer.example.com",
				"aud":       "identrail-api",
				"tenant_id": "tenant-1",
			},
		},
		{
			name: "groups invalid format",
			claims: map[string]any{
				"sub":          "subject-1",
				"iss":          "https://issuer.example.com",
				"aud":          "identrail-api",
				"tenant_id":    "tenant-1",
				"workspace_id": "workspace-1",
				"groups":       "engineering",
			},
		},
		{
			name: "roles invalid format",
			claims: map[string]any{
				"sub":          "subject-1",
				"iss":          "https://issuer.example.com",
				"aud":          "identrail-api",
				"tenant_id":    "tenant-1",
				"workspace_id": "workspace-1",
				"roles":        []any{"admin", 1},
			},
		},
		{
			name: "scope invalid format",
			claims: map[string]any{
				"sub":          "subject-1",
				"iss":          "https://issuer.example.com",
				"aud":          "identrail-api",
				"tenant_id":    "tenant-1",
				"workspace_id": "workspace-1",
				"scope":        []string{"read"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims := tc.claims
			if len(claims) == 0 {
				claims = baseClaims
			}
			verifier := &OIDCTokenVerifier{
				expectedIssuer: "https://issuer.example.com",
				expectedAud:    "identrail-api",
				tenantClaim:    "tenant_id",
				workspaceClaim: "workspace_id",
				groupsClaim:    "groups",
				rolesClaim:     "roles",
				verifier: fakeRawTokenVerifier{
					token: fakeClaimsDecoder{claims: claims},
				},
			}
			if _, err := verifier.VerifyToken(context.Background(), "token"); err == nil {
				t.Fatal("expected strict claim validation error")
			}
		})
	}

	optionalClaimsOK := &OIDCTokenVerifier{
		expectedIssuer: "https://issuer.example.com",
		expectedAud:    "identrail-api",
		tenantClaim:    "tenant_id",
		workspaceClaim: "workspace_id",
		groupsClaim:    "groups",
		rolesClaim:     "roles",
		verifier: fakeRawTokenVerifier{
			token: fakeClaimsDecoder{
				claims: map[string]any{
					"sub":          "subject-1",
					"iss":          "https://issuer.example.com",
					"aud":          "identrail-api",
					"tenant_id":    "tenant-1",
					"workspace_id": "workspace-1",
				},
			},
		},
	}
	if _, err := optionalClaimsOK.VerifyToken(context.Background(), "token"); err != nil {
		t.Fatalf("expected missing optional groups/roles claims to be accepted, got %v", err)
	}
}
