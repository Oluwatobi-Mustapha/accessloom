package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/app"
	"github.com/Oluwatobi-Mustapha/identrail/internal/config"
	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	awsprovider "github.com/Oluwatobi-Mustapha/identrail/internal/providers/aws"
	k8sprovider "github.com/Oluwatobi-Mustapha/identrail/internal/providers/kubernetes"
	"github.com/Oluwatobi-Mustapha/identrail/internal/repoexposure"
	"github.com/spf13/cobra"
)

const (
	defaultStateFile = ".identrail/last-findings.json"
	formatTable      = "table"
	formatJSON       = "json"
	defaultAPIURL    = "http://127.0.0.1:8080"
	defaultPolicySet = "central_authorization"
)

var defaultAWSFixturePaths = []string{
	"testdata/aws/role_with_policies.json",
	"testdata/aws/role_with_urlencoded_trust.json",
}

var defaultKubernetesFixturePaths = []string{
	"testdata/kubernetes/service_account_payments.json",
	"testdata/kubernetes/cluster_role_cluster_admin.json",
	"testdata/kubernetes/role_binding_cluster_admin.json",
	"testdata/kubernetes/pod_payments.json",
}

// BuildRootCmd creates the command tree with injected config and output writer.
func BuildRootCmd(cfg config.Config, out io.Writer) *cobra.Command {
	var stateFile string

	root := &cobra.Command{
		Use:   "identrail",
		Short: "Machine identity security scanner",
		Long:  "Identrail scans machine identities and reports typed cloud identity risks.",
	}

	root.SetOut(out)
	root.SetErr(out)
	root.PersistentFlags().StringVar(&stateFile, "state-file", defaultStateFile, "Path to local findings state file")

	root.AddCommand(buildScanCmd(cfg, out, &stateFile))
	root.AddCommand(buildFindingsCmd(out, &stateFile))
	root.AddCommand(buildRepoScanCmd(out))
	root.AddCommand(buildAuthzCmd(cfg, out))

	return root
}

func buildScanCmd(cfg config.Config, out io.Writer, stateFile *string) *cobra.Command {
	var fixtures []string
	var outputFormat string
	var staleAfterDays int
	var skipSave bool

	defaultFixtures := defaultFixturesForProvider(cfg)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a read-only scan",
		Long:  "Runs the provider scan pipeline (collector -> normalizer -> graph -> risk rules).",
		RunE: func(_ *cobra.Command, _ []string) error {
			if staleAfterDays < 1 {
				return fmt.Errorf("--stale-after-days must be at least 1")
			}

			formatter, err := parseOutputFormat(outputFormat)
			if err != nil {
				return err
			}

			scanner, err := buildScannerForProvider(cfg, fixtures, staleAfterDays)
			if err != nil {
				return err
			}

			result, err := scanner.Run(context.Background())
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			snapshot := findingsSnapshot{
				GeneratedAt: result.Completed,
				Assets:      result.Assets,
				Findings:    result.Findings,
			}
			if !skipSave {
				if err := saveSnapshot(*stateFile, snapshot); err != nil {
					return err
				}
			}

			if err := renderScanOutput(out, snapshot, formatter); err != nil {
				return err
			}

			if !skipSave {
				_, err = fmt.Fprintf(out, "Saved findings state to %s\n", *stateFile)
				if err != nil {
					return err
				}
			}
			return nil
		},
	}

	cmd.Flags().StringSliceVar(&fixtures, "fixture", append([]string(nil), defaultFixtures...), "Fixture JSON path(s) or directories for local scan")
	cmd.Flags().StringVar(&outputFormat, "output", formatTable, "Output format: table|json")
	cmd.Flags().IntVar(&staleAfterDays, "stale-after-days", 90, "Staleness threshold in days")
	cmd.Flags().BoolVar(&skipSave, "no-save", false, "Skip writing local findings state")

	return cmd
}

func buildFindingsCmd(out io.Writer, stateFile *string) *cobra.Command {
	var outputFormat string
	cmd := &cobra.Command{
		Use:   "findings",
		Short: "List findings from the most recent scan",
		RunE: func(_ *cobra.Command, _ []string) error {
			formatter, err := parseOutputFormat(outputFormat)
			if err != nil {
				return err
			}

			snapshot, err := loadSnapshot(*stateFile)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					_, writeErr := fmt.Fprintf(out, "No findings state found at %s. Run `identrail scan` first.\n", *stateFile)
					return writeErr
				}
				return err
			}
			return renderFindingsOutput(out, snapshot, formatter)
		},
	}

	cmd.Flags().StringVar(&outputFormat, "output", formatTable, "Output format: table|json")
	return cmd
}

func buildRepoScanCmd(out io.Writer) *cobra.Command {
	var (
		repository   string
		outputFormat string
		historyLimit int
		maxFindings  int
	)

	cmd := &cobra.Command{
		Use:   "repo-scan",
		Short: "Scan repository history for secret exposures and misconfigurations",
		Long:  "Scans all reachable commits for added secret material and scans HEAD configuration files for high-signal misconfigurations.",
		RunE: func(_ *cobra.Command, _ []string) error {
			if strings.TrimSpace(repository) == "" {
				return fmt.Errorf("--repo is required")
			}
			if historyLimit < 1 {
				return fmt.Errorf("--history-limit must be at least 1")
			}
			if maxFindings < 1 {
				return fmt.Errorf("--max-findings must be at least 1")
			}
			formatter, err := parseOutputFormat(outputFormat)
			if err != nil {
				return err
			}

			scanner := repoexposure.NewScanner(
				nil,
				repoexposure.WithHistoryLimit(historyLimit),
				repoexposure.WithMaxFindings(maxFindings),
			)
			result, err := scanner.ScanRepository(context.Background(), repository)
			if err != nil {
				return fmt.Errorf("repo scan failed: %w", err)
			}

			switch formatter {
			case outputJSON:
				return writeJSON(out, result)
			default:
				if _, err := fmt.Fprintf(
					out,
					"Repo scan completed: repo=%s commits=%d files=%d findings=%d truncated=%t\n",
					result.Repository,
					result.CommitsScanned,
					result.FilesScanned,
					len(result.Findings),
					result.Truncated,
				); err != nil {
					return err
				}
				return renderFindingsTable(out, result.Findings)
			}
		},
	}

	cmd.Flags().StringVar(&repository, "repo", "", "Repository target (owner/repo, URL, or local git path)")
	cmd.Flags().StringVar(&outputFormat, "output", formatTable, "Output format: table|json")
	cmd.Flags().IntVar(&historyLimit, "history-limit", 500, "Maximum number of commits to inspect for history secret exposure")
	cmd.Flags().IntVar(&maxFindings, "max-findings", 200, "Maximum findings to emit before truncating scan output")
	return cmd
}

func buildAuthzCmd(cfg config.Config, out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "authz",
		Short: "Authorization policy lifecycle operations",
	}
	cmd.AddCommand(buildAuthzRollbackCmd(cfg, out))
	return cmd
}

func buildAuthzRollbackCmd(cfg config.Config, out io.Writer) *cobra.Command {
	var (
		apiURL        string
		apiKey        string
		tenantID      string
		workspaceID   string
		policySetID   string
		targetVersion int
		actor         string
		timeout       time.Duration
		outputFormat  string
	)

	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Rollback active authorization policy version immediately",
		Long:  "Issues one rollback API request that resets rollout mode to disabled and switches active policy version immediately.",
		RunE: func(_ *cobra.Command, _ []string) error {
			if targetVersion <= 0 {
				return fmt.Errorf("--target-version must be greater than zero")
			}
			formatter, err := parseOutputFormat(outputFormat)
			if err != nil {
				return err
			}
			rollbackURL := strings.TrimRight(strings.TrimSpace(apiURL), "/") + "/v1/authz/policies/rollback"
			if strings.TrimSpace(apiURL) == "" {
				return fmt.Errorf("--api-url is required")
			}
			requestBody := authzPolicyRollbackCLIRequest{
				PolicySetID:   strings.TrimSpace(policySetID),
				TargetVersion: targetVersion,
				Actor:         strings.TrimSpace(actor),
			}
			payload, err := json.Marshal(requestBody)
			if err != nil {
				return fmt.Errorf("encode rollback request: %w", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodPost, rollbackURL, bytes.NewReader(payload))
			if err != nil {
				return fmt.Errorf("build rollback request: %w", err)
			}
			req.Header.Set("Content-Type", "application/json")
			if normalizedKey := strings.TrimSpace(apiKey); normalizedKey != "" {
				req.Header.Set("X-API-Key", normalizedKey)
			}
			if normalizedTenant := strings.TrimSpace(tenantID); normalizedTenant != "" {
				req.Header.Set("X-Identrail-Tenant-ID", normalizedTenant)
			}
			if normalizedWorkspace := strings.TrimSpace(workspaceID); normalizedWorkspace != "" {
				req.Header.Set("X-Identrail-Workspace-ID", normalizedWorkspace)
			}

			resp, err := (&http.Client{Timeout: timeout}).Do(req)
			if err != nil {
				return fmt.Errorf("rollback request failed: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				var apiErr authzPolicyRollbackCLIErrorResponse
				if err := json.NewDecoder(resp.Body).Decode(&apiErr); err == nil && strings.TrimSpace(apiErr.Error) != "" {
					return fmt.Errorf("rollback request failed: %s (status %d)", strings.TrimSpace(apiErr.Error), resp.StatusCode)
				}
				return fmt.Errorf("rollback request failed with status %d", resp.StatusCode)
			}

			var response authzPolicyRollbackCLIResponse
			if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
				return fmt.Errorf("decode rollback response: %w", err)
			}
			switch formatter {
			case outputJSON:
				return writeJSON(out, response)
			default:
				return renderAuthzRollbackOutput(out, response)
			}
		},
	}

	cmd.Flags().StringVar(&apiURL, "api-url", defaultCLIAPIURL(), "Identrail API base URL")
	cmd.Flags().StringVar(&apiKey, "api-key", strings.TrimSpace(os.Getenv("IDENTRAIL_API_KEY")), "API key used for rollback request")
	cmd.Flags().StringVar(&tenantID, "tenant-id", strings.TrimSpace(cfg.DefaultTenantID), "Tenant scope header for rollback request")
	cmd.Flags().StringVar(&workspaceID, "workspace-id", strings.TrimSpace(cfg.DefaultWorkspaceID), "Workspace scope header for rollback request")
	cmd.Flags().StringVar(&policySetID, "policy-set-id", defaultPolicySet, "Policy set to rollback")
	cmd.Flags().IntVar(&targetVersion, "target-version", 0, "Target policy version to make active")
	cmd.Flags().StringVar(&actor, "actor", "", "Actor identifier recorded in rollback lifecycle event")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "HTTP timeout for rollback request")
	cmd.Flags().StringVar(&outputFormat, "output", formatTable, "Output format: table|json")
	return cmd
}

func defaultCLIAPIURL() string {
	if configured := strings.TrimSpace(os.Getenv("IDENTRAIL_API_URL")); configured != "" {
		return configured
	}
	return defaultAPIURL
}

func renderAuthzRollbackOutput(out io.Writer, response authzPolicyRollbackCLIResponse) error {
	_, err := fmt.Fprintf(
		out,
		"Rollback applied: policy_set=%s active_version=%d mode=%s previous_effective=%s\n",
		strings.TrimSpace(response.PolicySetID),
		response.ActiveVersion,
		strings.TrimSpace(response.RolloutMode),
		formatOptionalInt(response.PreviousEffective),
	)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(
		out,
		"Previous active=%s candidate=%s updated_at=%s\n",
		formatOptionalInt(response.PreviousActiveVersion),
		formatOptionalInt(response.PreviousCandidateVersion),
		response.UpdatedAt.Format(time.RFC3339),
	)
	return err
}

type authzPolicyRollbackCLIRequest struct {
	PolicySetID   string `json:"policy_set_id"`
	TargetVersion int    `json:"target_version"`
	Actor         string `json:"actor,omitempty"`
}

type authzPolicyRollbackCLIResponse struct {
	PolicySetID              string    `json:"policy_set_id"`
	PreviousEffective        *int      `json:"previous_effective_version,omitempty"`
	PreviousActiveVersion    *int      `json:"previous_active_version,omitempty"`
	PreviousCandidateVersion *int      `json:"previous_candidate_version,omitempty"`
	ActiveVersion            int       `json:"active_version"`
	RolloutMode              string    `json:"rollout_mode"`
	UpdatedAt                time.Time `json:"updated_at"`
}

type authzPolicyRollbackCLIErrorResponse struct {
	Error string `json:"error"`
}

func formatOptionalInt(value *int) string {
	if value == nil {
		return "none"
	}
	return fmt.Sprintf("%d", *value)
}

// Execute runs the root command with externalized args for testability.
func Execute(cfg config.Config, args []string, out io.Writer) error {
	cmd := BuildRootCmd(cfg, out)
	cmd.SetArgs(args)
	return cmd.Execute()
}

func defaultFixturesForProvider(cfg config.Config) []string {
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "kubernetes":
		if len(cfg.KubernetesFixturePath) > 0 {
			return cfg.KubernetesFixturePath
		}
		return defaultKubernetesFixturePaths
	default:
		if len(cfg.AWSFixturePath) > 0 {
			return cfg.AWSFixturePath
		}
		return defaultAWSFixturePaths
	}
}

func buildScannerForProvider(cfg config.Config, fixtures []string, staleAfterDays int) (app.Scanner, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "aws":
		switch strings.ToLower(strings.TrimSpace(cfg.AWSSource)) {
		case "", "fixture":
			return app.Scanner{
				Collector:            awsprovider.NewFixtureCollector(fixtures),
				Normalizer:           awsprovider.NewRoleNormalizer(),
				PermissionResolver:   awsprovider.NewPolicyPermissionResolver(),
				RelationshipResolver: awsprovider.NewRelationshipBuilder(),
				RiskRuleSet:          awsprovider.NewRuleSet(awsprovider.WithStaleAfter(time.Duration(staleAfterDays) * 24 * time.Hour)),
			}, nil
		case "sdk":
			iamAPI, err := awsprovider.NewSDKIAMAPI(cfg.AWSRegion, cfg.AWSProfile)
			if err != nil {
				return app.Scanner{}, fmt.Errorf("initialize aws sdk collector: %w", err)
			}
			return app.Scanner{
				Collector:            awsprovider.NewCollector(iamAPI),
				Normalizer:           awsprovider.NewRoleNormalizer(),
				PermissionResolver:   awsprovider.NewPolicyPermissionResolver(),
				RelationshipResolver: awsprovider.NewRelationshipBuilder(),
				RiskRuleSet:          awsprovider.NewRuleSet(awsprovider.WithStaleAfter(time.Duration(staleAfterDays) * 24 * time.Hour)),
			}, nil
		default:
			return app.Scanner{}, fmt.Errorf("unsupported aws source %q", cfg.AWSSource)
		}
	case "kubernetes":
		switch strings.ToLower(strings.TrimSpace(cfg.KubernetesSource)) {
		case "", "fixture":
			return app.Scanner{
				Collector:            k8sprovider.NewFixtureCollector(fixtures),
				Normalizer:           k8sprovider.NewNormalizer(),
				PermissionResolver:   k8sprovider.NewPermissionResolver(),
				RelationshipResolver: k8sprovider.NewRelationshipResolver(),
				RiskRuleSet:          k8sprovider.NewRuleSet(),
			}, nil
		case "kubectl":
			return app.Scanner{
				Collector:            k8sprovider.NewKubectlCollector(cfg.KubectlPath, cfg.KubeContext, nil),
				Normalizer:           k8sprovider.NewNormalizer(),
				PermissionResolver:   k8sprovider.NewPermissionResolver(),
				RelationshipResolver: k8sprovider.NewRelationshipResolver(),
				RiskRuleSet:          k8sprovider.NewRuleSet(),
			}, nil
		default:
			return app.Scanner{}, fmt.Errorf("unsupported kubernetes source %q", cfg.KubernetesSource)
		}
	default:
		return app.Scanner{}, fmt.Errorf("unsupported provider %q", cfg.Provider)
	}
}

type outputFormat int

const (
	outputTable outputFormat = iota
	outputJSON
)

func parseOutputFormat(raw string) (outputFormat, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case formatTable:
		return outputTable, nil
	case formatJSON:
		return outputJSON, nil
	default:
		return outputTable, fmt.Errorf("invalid --output %q (expected table|json)", raw)
	}
}

type findingsSnapshot struct {
	GeneratedAt time.Time        `json:"generated_at"`
	Assets      int              `json:"assets"`
	Findings    []domain.Finding `json:"findings"`
}

func saveSnapshot(path string, snapshot findingsSnapshot) error {
	absolute := normalizeStatePath(path)
	if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("encode findings snapshot: %w", err)
	}
	if err := os.WriteFile(absolute, data, 0o600); err != nil {
		return fmt.Errorf("write findings snapshot: %w", err)
	}
	return nil
}

func loadSnapshot(path string) (findingsSnapshot, error) {
	absolute := normalizeStatePath(path)
	data, err := os.ReadFile(absolute)
	if err != nil {
		return findingsSnapshot{}, err
	}

	var snapshot findingsSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return findingsSnapshot{}, fmt.Errorf("decode findings snapshot: %w", err)
	}
	return snapshot, nil
}

func normalizeStatePath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return defaultStateFile
	}
	return trimmed
}

func renderScanOutput(out io.Writer, snapshot findingsSnapshot, format outputFormat) error {
	switch format {
	case outputJSON:
		return writeJSON(out, snapshot)
	default:
		_, err := fmt.Fprintf(out, "Scan completed: %d assets, %d findings\n", snapshot.Assets, len(snapshot.Findings))
		if err != nil {
			return err
		}
		return renderFindingsTable(out, snapshot.Findings)
	}
}

func renderFindingsOutput(out io.Writer, snapshot findingsSnapshot, format outputFormat) error {
	switch format {
	case outputJSON:
		return writeJSON(out, snapshot)
	default:
		_, err := fmt.Fprintf(out, "Last scan: %s | assets: %d | findings: %d\n", snapshot.GeneratedAt.Format(time.RFC3339), snapshot.Assets, len(snapshot.Findings))
		if err != nil {
			return err
		}
		return renderFindingsTable(out, snapshot.Findings)
	}
}

func writeJSON(out io.Writer, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "%s\n", data)
	return err
}

func renderFindingsTable(out io.Writer, findings []domain.Finding) error {
	if len(findings) == 0 {
		_, err := fmt.Fprintln(out, "No findings.")
		return err
	}

	sorted := make([]domain.Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		leftSeverity := severitySortRank(sorted[i].Severity)
		rightSeverity := severitySortRank(sorted[j].Severity)
		if leftSeverity == rightSeverity {
			if sorted[i].Type == sorted[j].Type {
				return sorted[i].Title < sorted[j].Title
			}
			return sorted[i].Type < sorted[j].Type
		}
		return leftSeverity > rightSeverity
	})

	for i, finding := range sorted {
		_, err := fmt.Fprintf(
			out,
			"%d. [%s] %s (%s)\n   %s\n",
			i+1,
			strings.ToUpper(string(finding.Severity)),
			finding.Title,
			finding.Type,
			finding.HumanSummary,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func severitySortRank(severity domain.FindingSeverity) int {
	switch severity {
	case domain.SeverityCritical:
		return 5
	case domain.SeverityHigh:
		return 4
	case domain.SeverityMedium:
		return 3
	case domain.SeverityLow:
		return 2
	case domain.SeverityInfo:
		return 1
	default:
		return 0
	}
}
