package repoexposure

import (
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
)

type secretRule struct {
	ID          string
	Severity    domain.FindingSeverity
	Title       string
	Summary     string
	Remediation string
	Pattern     *regexp.Regexp
}

var secretRules = []secretRule{
	{
		ID:          "aws_access_key_id",
		Severity:    domain.SeverityHigh,
		Title:       "Potential AWS access key exposed in commit history",
		Summary:     "A line added in commit history appears to contain an AWS access key identifier.",
		Remediation: "Rotate the key, purge secrets from history, and move credentials to a secret manager.",
		Pattern:     regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	},
	{
		ID:          "aws_secret_access_key",
		Severity:    domain.SeverityCritical,
		Title:       "Potential AWS secret key exposed in commit history",
		Summary:     "A line added in commit history appears to contain an AWS secret access key.",
		Remediation: "Rotate affected credentials immediately and replace static secrets with short-lived credentials.",
		Pattern:     regexp.MustCompile(`(?i)\baws(?:_| |\.)?(?:secret(?:_| |\.)?)?access(?:_| |\.)?key(?:_| |\.)?=?\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
	},
	{
		ID:          "github_token",
		Severity:    domain.SeverityCritical,
		Title:       "Potential GitHub token exposed in commit history",
		Summary:     "A line added in commit history appears to contain a GitHub token.",
		Remediation: "Revoke the token immediately, rotate dependent credentials, and enforce secret scanning in CI.",
		Pattern:     regexp.MustCompile(`\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,})\b`),
	},
	{
		ID:          "slack_token",
		Severity:    domain.SeverityHigh,
		Title:       "Potential Slack token exposed in commit history",
		Summary:     "A line added in commit history appears to contain a Slack token.",
		Remediation: "Revoke and rotate the token in Slack, then remove token usage from repository files.",
		Pattern:     regexp.MustCompile(`\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{10,}\b`),
	},
	{
		ID:          "private_key_material",
		Severity:    domain.SeverityCritical,
		Title:       "Private key material exposed in commit history",
		Summary:     "A line added in commit history contains private key header material.",
		Remediation: "Revoke and rotate affected keys, remove key files from history, and store keys in a vault/KMS.",
		Pattern:     regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`),
	},
}

type lineMisconfigRule struct {
	ID          string
	Severity    domain.FindingSeverity
	Title       string
	Summary     string
	Remediation string
	Pattern     *regexp.Regexp
}

type fileMisconfigRule struct {
	ID          string
	Severity    domain.FindingSeverity
	Title       string
	Summary     string
	Remediation string
	Pattern     *regexp.Regexp
}

var lineMisconfigRules = []lineMisconfigRule{
	{
		ID:          "workflow_write_all_permissions",
		Severity:    domain.SeverityHigh,
		Title:       "GitHub workflow grants broad write permissions",
		Summary:     "Workflow permissions are set to write-all, increasing automation blast radius.",
		Remediation: "Restrict workflow permissions to least-privilege per job and avoid global write-all.",
		Pattern:     regexp.MustCompile(`(?i)^\s*permissions:\s*write-all\s*$`),
	},
	{
		ID:          "workflow_pull_request_target",
		Severity:    domain.SeverityMedium,
		Title:       "GitHub workflow uses pull_request_target trigger",
		Summary:     "pull_request_target can execute with elevated token context if not strictly controlled.",
		Remediation: "Use pull_request where possible, pin actions, and harden token permissions for untrusted PR code.",
		Pattern:     regexp.MustCompile(`(?i)^\s*pull_request_target\s*:\s*$`),
	},
	{
		ID:          "k8s_privileged_true",
		Severity:    domain.SeverityHigh,
		Title:       "Kubernetes manifest enables privileged container",
		Summary:     "A container runs with privileged=true, which can bypass workload isolation boundaries.",
		Remediation: "Set privileged=false and apply Pod Security standards with least-privilege securityContext.",
		Pattern:     regexp.MustCompile(`(?i)^\s*privileged:\s*true\s*$`),
	},
	{
		ID:          "terraform_public_s3_acl",
		Severity:    domain.SeverityHigh,
		Title:       "Terraform config enables public S3 ACL",
		Summary:     "Terraform file sets a public S3 ACL, which can expose data externally.",
		Remediation: "Use private ACLs and explicit bucket policies with least-privilege principals.",
		Pattern:     regexp.MustCompile(`(?i)^\s*acl\s*=\s*"public-(?:read|read-write)"\s*$`),
	},
	{
		ID:          "docker_latest_tag",
		Severity:    domain.SeverityMedium,
		Title:       "Docker image uses mutable latest tag",
		Summary:     "Using :latest weakens supply-chain determinism and patch traceability.",
		Remediation: "Pin base images by immutable version/digest and review updates through CI.",
		Pattern:     regexp.MustCompile(`(?i)^FROM\s+\S+:latest(?:\s+AS\s+\S+)?\s*$`),
	},
}

var fileMisconfigRules = []fileMisconfigRule{
	{
		ID:          "terraform_open_ssh_rdp",
		Severity:    domain.SeverityHigh,
		Title:       "Terraform security group exposes SSH/RDP to the internet",
		Summary:     "Config appears to allow 0.0.0.0/0 access to privileged management ports.",
		Remediation: "Restrict source CIDRs and route administrative access through bastion/VPN controls.",
		Pattern:     regexp.MustCompile(`(?is)from_port\s*=\s*(22|3389).*?(?:cidr_blocks|ipv6_cidr_blocks)\s*=\s*\[[^\]]*(?:0\.0\.0\.0/0|::/0)`),
	},
}

func detectSecretFindings(repo string, commit string, path string, line int, text string, detectedAt time.Time) []domain.Finding {
	normalized := strings.TrimSpace(text)
	if normalized == "" {
		return nil
	}
	findings := []domain.Finding{}
	for _, rule := range secretRules {
		match := rule.Pattern.FindString(normalized)
		if strings.TrimSpace(match) == "" {
			continue
		}
		sanitized := redactMatch(normalized, match)
		fingerprint := hashSHA256(match)
		id := hashDeterministicID("repo-secret", repo, commit, path, strconv.Itoa(line), rule.ID, fingerprint)
		findings = append(findings, domain.Finding{
			ID:           "finding:" + id,
			Type:         domain.FindingSecretExposure,
			Severity:     rule.Severity,
			Title:        rule.Title,
			HumanSummary: rule.Summary,
			Path:         []string{path},
			Evidence: map[string]any{
				"repository":          repo,
				"commit":              commit,
				"file_path":           path,
				"line_number":         line,
				"detector":            rule.ID,
				"secret_fingerprint":  fingerprint,
				"redacted_line_snip":  sanitized,
				"history_source":      "commit_diff",
				"raw_secret_stored":   false,
				"secret_value_masked": true,
			},
			Remediation: rule.Remediation,
			CreatedAt:   detectedAt,
		})
	}
	return findings
}

func detectMisconfigFindings(repo string, path string, content []byte, detectedAt time.Time) []domain.Finding {
	data := string(content)
	findings := []domain.Finding{}
	seen := map[string]struct{}{}

	lines := strings.Split(data, "\n")
	for index, line := range lines {
		lineNumber := index + 1
		for _, rule := range lineMisconfigRules {
			if !rule.Pattern.MatchString(line) {
				continue
			}
			key := fmt.Sprintf("%s:%d:%s", path, lineNumber, rule.ID)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			id := hashDeterministicID("repo-misconfig", repo, path, strconv.Itoa(lineNumber), rule.ID, line)
			findings = append(findings, domain.Finding{
				ID:           "finding:" + id,
				Type:         domain.FindingRepoMisconfig,
				Severity:     rule.Severity,
				Title:        rule.Title,
				HumanSummary: rule.Summary,
				Path:         []string{path},
				Evidence: map[string]any{
					"repository":      repo,
					"commit":          "HEAD",
					"file_path":       path,
					"line_number":     lineNumber,
					"detector":        rule.ID,
					"line_snippet":    strings.TrimSpace(line),
					"history_source":  "head_snapshot",
					"raw_secret_data": false,
				},
				Remediation: rule.Remediation,
				CreatedAt:   detectedAt,
			})
		}
	}

	for _, rule := range fileMisconfigRules {
		loc := rule.Pattern.FindStringIndex(data)
		if len(loc) != 2 {
			continue
		}
		lineNumber := lineForOffset(data, loc[0])
		matchText := strings.TrimSpace(rule.Pattern.FindString(data))
		if len(matchText) > 240 {
			matchText = matchText[:240] + "..."
		}
		key := fmt.Sprintf("%s:%d:%s", path, lineNumber, rule.ID)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		id := hashDeterministicID("repo-misconfig", repo, path, strconv.Itoa(lineNumber), rule.ID, matchText)
		findings = append(findings, domain.Finding{
			ID:           "finding:" + id,
			Type:         domain.FindingRepoMisconfig,
			Severity:     rule.Severity,
			Title:        rule.Title,
			HumanSummary: rule.Summary,
			Path:         []string{path},
			Evidence: map[string]any{
				"repository":      repo,
				"commit":          "HEAD",
				"file_path":       path,
				"line_number":     lineNumber,
				"detector":        rule.ID,
				"match_snippet":   matchText,
				"history_source":  "head_snapshot",
				"raw_secret_data": false,
			},
			Remediation: rule.Remediation,
			CreatedAt:   detectedAt,
		})
	}

	return findings
}

func shouldInspectMisconfiguration(path string) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	if lower == "" {
		return false
	}
	base := strings.ToLower(filepath.Base(lower))
	if strings.HasPrefix(lower, ".github/workflows/") {
		return true
	}
	if base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") {
		return true
	}
	for _, ext := range []string{".tf", ".yml", ".yaml"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func lineForOffset(content string, offset int) int {
	if offset <= 0 {
		return 1
	}
	return bytes.Count([]byte(content[:offset]), []byte("\n")) + 1
}
