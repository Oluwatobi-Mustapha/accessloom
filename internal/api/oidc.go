package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	defaultOIDCTenantClaim    = "tenant_id"
	defaultOIDCWorkspaceClaim = "workspace_id"
	defaultOIDCGroupsClaim    = "groups"
	defaultOIDCRolesClaim     = "roles"
)

// OIDCTokenVerifier validates OIDC bearer tokens using issuer discovery and JWKS verification.
type OIDCTokenVerifier struct {
	verifier       rawTokenVerifier
	expectedIssuer string
	expectedAud    string
	tenantClaim    string
	workspaceClaim string
	groupsClaim    string
	rolesClaim     string
}

type tokenClaimsDecoder interface {
	Claims(v interface{}) error
}

type rawTokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (tokenClaimsDecoder, error)
}

type oidcRawTokenVerifier struct {
	verifier *oidc.IDTokenVerifier
}

func (v oidcRawTokenVerifier) Verify(ctx context.Context, rawToken string) (tokenClaimsDecoder, error) {
	idToken, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, err
	}
	return idToken, nil
}

// NewOIDCTokenVerifier constructs a verifier from issuer URL and expected audience.
func NewOIDCTokenVerifier(
	ctx context.Context,
	issuerURL string,
	audience string,
	tenantClaim string,
	workspaceClaim string,
	groupsClaim string,
	rolesClaim string,
) (*OIDCTokenVerifier, error) {
	issuer := strings.TrimSpace(issuerURL)
	if issuer == "" {
		return nil, fmt.Errorf("oidc issuer url is required")
	}
	clientID := strings.TrimSpace(audience)
	if clientID == "" {
		return nil, fmt.Errorf("oidc audience is required")
	}
	tenantClaimName := strings.TrimSpace(tenantClaim)
	if tenantClaimName == "" {
		tenantClaimName = defaultOIDCTenantClaim
	}
	workspaceClaimName := strings.TrimSpace(workspaceClaim)
	if workspaceClaimName == "" {
		workspaceClaimName = defaultOIDCWorkspaceClaim
	}
	groupsClaimName := strings.TrimSpace(groupsClaim)
	if groupsClaimName == "" {
		groupsClaimName = defaultOIDCGroupsClaim
	}
	rolesClaimName := strings.TrimSpace(rolesClaim)
	if rolesClaimName == "" {
		rolesClaimName = defaultOIDCRolesClaim
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("discover oidc provider: %w", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	return &OIDCTokenVerifier{
		verifier:       oidcRawTokenVerifier{verifier: verifier},
		expectedIssuer: issuer,
		expectedAud:    clientID,
		tenantClaim:    tenantClaimName,
		workspaceClaim: workspaceClaimName,
		groupsClaim:    groupsClaimName,
		rolesClaim:     rolesClaimName,
	}, nil
}

// VerifyToken verifies one raw bearer token and extracts normalized claims.
func (v *OIDCTokenVerifier) VerifyToken(ctx context.Context, rawToken string) (VerifiedToken, error) {
	if v == nil || v.verifier == nil {
		return VerifiedToken{}, fmt.Errorf("oidc verifier is not configured")
	}

	token, err := v.verifier.Verify(ctx, strings.TrimSpace(rawToken))
	if err != nil {
		return VerifiedToken{}, err
	}

	var claims map[string]any
	if err := token.Claims(&claims); err != nil {
		return VerifiedToken{}, fmt.Errorf("decode oidc claims: %w", err)
	}

	subject, err := requiredClaimString(claims, "sub")
	if err != nil {
		return VerifiedToken{}, err
	}
	issuer, err := requiredClaimString(claims, "iss")
	if err != nil {
		return VerifiedToken{}, err
	}
	if issuer != v.expectedIssuer {
		return VerifiedToken{}, fmt.Errorf("oidc claim \"iss\" mismatch")
	}
	audiences, err := requiredAudienceClaim(claims)
	if err != nil {
		return VerifiedToken{}, err
	}
	if !stringSliceContains(audiences, v.expectedAud) {
		return VerifiedToken{}, fmt.Errorf("oidc claim \"aud\" missing expected audience")
	}
	tenantID, err := requiredClaimString(claims, v.tenantClaim)
	if err != nil {
		return VerifiedToken{}, err
	}
	workspaceID, err := requiredClaimString(claims, v.workspaceClaim)
	if err != nil {
		return VerifiedToken{}, err
	}
	groups, err := optionalStringArrayClaim(claims, v.groupsClaim)
	if err != nil {
		return VerifiedToken{}, err
	}
	roles, err := optionalStringArrayClaim(claims, v.rolesClaim)
	if err != nil {
		return VerifiedToken{}, err
	}
	scopes, err := extractTokenScopes(claims)
	if err != nil {
		return VerifiedToken{}, err
	}

	return VerifiedToken{
		Subject:     subject,
		Issuer:      issuer,
		Audiences:   audiences,
		TenantID:    tenantID,
		WorkspaceID: workspaceID,
		Groups:      groups,
		Roles:       roles,
		Scopes:      scopes,
	}, nil
}

func requiredClaimString(claims map[string]any, claim string) (string, error) {
	raw, ok := claims[claim]
	if !ok {
		return "", fmt.Errorf("missing required oidc claim %q", claim)
	}
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("oidc claim %q must be a string", claim)
	}
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return "", fmt.Errorf("oidc claim %q must be non-empty", claim)
	}
	return normalized, nil
}

func optionalStringArrayClaim(claims map[string]any, claim string) ([]string, error) {
	raw, ok := claims[claim]
	if !ok {
		return []string{}, nil
	}
	parsed, err := claimStringArray(raw, claim)
	if err != nil {
		return nil, err
	}
	return parsed, nil
}

func claimStringArray(raw any, claim string) ([]string, error) {
	switch values := raw.(type) {
	case []any:
		result := make([]string, 0, len(values))
		for _, item := range values {
			value, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("oidc claim %q must be an array of strings", claim)
			}
			normalized := strings.TrimSpace(value)
			if normalized == "" {
				return nil, fmt.Errorf("oidc claim %q must contain non-empty string values", claim)
			}
			result = append(result, normalized)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("oidc claim %q must be an array of strings", claim)
	}
}

func requiredAudienceClaim(claims map[string]any) ([]string, error) {
	raw, ok := claims["aud"]
	if !ok {
		return nil, fmt.Errorf("missing required oidc claim %q", "aud")
	}
	switch aud := raw.(type) {
	case string:
		normalized := strings.TrimSpace(aud)
		if normalized == "" {
			return nil, fmt.Errorf("oidc claim %q must be non-empty", "aud")
		}
		return []string{normalized}, nil
	case []string:
		if len(aud) == 0 {
			return nil, fmt.Errorf("oidc claim %q must be non-empty", "aud")
		}
		result := make([]string, 0, len(aud))
		for _, item := range aud {
			normalized := strings.TrimSpace(item)
			if normalized == "" {
				return nil, fmt.Errorf("oidc claim %q must contain non-empty values", "aud")
			}
			result = append(result, normalized)
		}
		return result, nil
	case []any:
		if len(aud) == 0 {
			return nil, fmt.Errorf("oidc claim %q must be non-empty", "aud")
		}
		result := make([]string, 0, len(aud))
		for _, item := range aud {
			value, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("oidc claim %q must be a string or array of strings", "aud")
			}
			normalized := strings.TrimSpace(value)
			if normalized == "" {
				return nil, fmt.Errorf("oidc claim %q must contain non-empty values", "aud")
			}
			result = append(result, normalized)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("oidc claim %q must be a string or array of strings", "aud")
	}
}

func extractTokenScopes(claims map[string]any) ([]string, error) {
	scopes := []string{}
	if rawScope, ok := claims["scope"]; ok {
		scopeString, ok := rawScope.(string)
		if !ok {
			return nil, fmt.Errorf("oidc claim %q must be a string", "scope")
		}
		normalized := strings.TrimSpace(scopeString)
		if normalized != "" {
			scopes = append(scopes, strings.Fields(normalized)...)
		}
	}
	if rawSCP, ok := claims["scp"]; ok {
		switch typed := rawSCP.(type) {
		case string:
			normalized := strings.TrimSpace(typed)
			if normalized != "" {
				scopes = append(scopes, strings.Fields(normalized)...)
			}
		default:
			parsed, err := claimStringArray(rawSCP, "scp")
			if err != nil {
				return nil, err
			}
			scopes = append(scopes, parsed...)
		}
	}
	return scopes, nil
}

func stringSliceContains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
