package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"github.com/spf13/cobra"
)

const (
	defaultStateFile = ".identrail/last-findings.json"
	formatTable      = "table"
	formatJSON       = "json"
)

var defaultAWSFixturePaths = []string{
	"testdata/aws/role_with_policies.json",
	"testdata/aws/role_with_urlencoded_trust.json",
}

var defaultKubernetesFixturePaths = []string{
	"testdata/kubernetes/service_account_payments.json",
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
		if sorted[i].Severity == sorted[j].Severity {
			if sorted[i].Type == sorted[j].Type {
				return sorted[i].Title < sorted[j].Title
			}
			return sorted[i].Type < sorted[j].Type
		}
		return sorted[i].Severity < sorted[j].Severity
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
