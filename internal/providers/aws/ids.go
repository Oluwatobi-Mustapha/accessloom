package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
)

var nonAlphaNumeric = regexp.MustCompile(`[^a-z0-9]+`)

func identityIDFromARN(arn string) string {
	return "aws:identity:" + strings.TrimSpace(arn)
}

func permissionPolicyID(identityID, policyName string, index int) string {
	normalizedName := normalizeName(policyName)
	if normalizedName == "" {
		normalizedName = fmt.Sprintf("policy-%d", index)
	}
	return fmt.Sprintf("%s:policy:%s", identityID, normalizedName)
}

func trustPolicyID(identityID string) string {
	return identityID + ":policy:trust"
}

func principalNodeID(principalARN string, arnToIdentity map[string]string) string {
	principal := strings.TrimSpace(principalARN)
	if principal == "" {
		return ""
	}
	if mapped, ok := arnToIdentity[principal]; ok {
		return mapped
	}
	return "aws:principal:" + principal
}

func accessNodeID(action, resource string) string {
	escapedAction := url.QueryEscape(strings.TrimSpace(action))
	escapedResource := url.QueryEscape(strings.TrimSpace(resource))
	return fmt.Sprintf("aws:access:%s:%s", escapedAction, escapedResource)
}

func relationshipID(relationshipType domain.RelationshipType, fromNodeID, toNodeID string) string {
	raw := string(relationshipType) + "|" + fromNodeID + "|" + toNodeID
	sum := sha256.Sum256([]byte(raw))
	return "aws:rel:" + hex.EncodeToString(sum[:16])
}

func normalizeName(input string) string {
	normalized := strings.ToLower(strings.TrimSpace(input))
	normalized = nonAlphaNumeric.ReplaceAllString(normalized, "-")
	return strings.Trim(normalized, "-")
}
