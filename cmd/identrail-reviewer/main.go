package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/Oluwatobi-Mustapha/identrail/internal/identrailreviewer/audit"
	"github.com/Oluwatobi-Mustapha/identrail/internal/identrailreviewer/baseline"
	"github.com/Oluwatobi-Mustapha/identrail/internal/identrailreviewer/enforcement"
	"github.com/Oluwatobi-Mustapha/identrail/internal/identrailreviewer/model"
	"github.com/Oluwatobi-Mustapha/identrail/internal/identrailreviewer/policy"
	"github.com/Oluwatobi-Mustapha/identrail/internal/identrailreviewer/review"
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: identrail-reviewer <review-pr|review-issue|enforce> [flags]")
	}

	switch os.Args[1] {
	case "review-pr":
		reviewPR(os.Args[2:])
	case "review-issue":
		reviewIssue(os.Args[2:])
	case "enforce":
		enforceGate(os.Args[2:])
	default:
		fatal("unknown subcommand: " + os.Args[1] + " (expected: review-pr, review-issue, enforce)")
	}
}

func reviewPR(args []string) {
	fs := flag.NewFlagSet("review-pr", flag.ExitOnError)
	repoRoot := fs.String("repo-root", ".", "repository root")
	eventPath := fs.String("event-path", "", "GitHub event payload path")
	changedFilesPath := fs.String("changed-files", "", "changed files JSON path")
	policyPath := fs.String("policy", "", "review policy JSON path")
	baselinePath := fs.String("baseline", "", "baseline JSON path for new-findings-only filtering")
	auditPath := fs.String("audit-log", "", "audit JSONL output path")
	outputPath := fs.String("output", "", "output path for review result")
	_ = fs.Parse(args)

	if *eventPath == "" || *changedFilesPath == "" || *outputPath == "" {
		fatal("review-pr requires --event-path, --changed-files, and --output")
	}

	eventBytes, err := os.ReadFile(*eventPath)
	if err != nil {
		fatal(err.Error())
	}

	var event model.PullRequestEvent
	if err := json.Unmarshal(eventBytes, &event); err != nil {
		fatal("failed to parse PR event payload: " + err.Error())
	}
	if event.PullRequest.Number == 0 {
		fatal(errors.New("event payload does not contain pull request context").Error())
	}

	changedBytes, err := os.ReadFile(*changedFilesPath)
	if err != nil {
		fatal(err.Error())
	}

	var changedFiles []model.ChangedFile
	if err := json.Unmarshal(changedBytes, &changedFiles); err != nil {
		fatal("failed to parse changed files JSON: " + err.Error())
	}

	labels := make([]string, 0, len(event.PullRequest.Labels))
	for _, l := range event.PullRequest.Labels {
		labels = append(labels, l.Name)
	}

	result := review.ReviewPR(
		*repoRoot,
		event.PullRequest.Number,
		event.PullRequest.Title,
		event.PullRequest.Body,
		labels,
		changedFiles,
	)

	cfg, err := policy.Load(*policyPath)
	if err != nil {
		fatal("failed to load policy: " + err.Error())
	}
	result = policy.Apply(cfg, result)

	baselineCfg, err := baseline.Load(*baselinePath)
	if err != nil {
		fatal("failed to load baseline: " + err.Error())
	}
	result = baseline.Apply(baselineCfg, result)

	if err := audit.Append(*auditPath, result); err != nil {
		fatal("failed to write audit log: " + err.Error())
	}
	writeJSON(*outputPath, result)
}

func reviewIssue(args []string) {
	fs := flag.NewFlagSet("review-issue", flag.ExitOnError)
	eventPath := fs.String("event-path", "", "GitHub event payload path")
	policyPath := fs.String("policy", "", "review policy JSON path")
	auditPath := fs.String("audit-log", "", "audit JSONL output path")
	outputPath := fs.String("output", "", "output path for review result")
	_ = fs.Parse(args)

	if *eventPath == "" || *outputPath == "" {
		fatal("review-issue requires --event-path and --output")
	}

	eventBytes, err := os.ReadFile(*eventPath)
	if err != nil {
		fatal(err.Error())
	}

	var event model.IssueEvent
	if err := json.Unmarshal(eventBytes, &event); err != nil {
		fatal("failed to parse issue event payload: " + err.Error())
	}

	if event.Issue.Number == 0 {
		fatal(errors.New("event payload does not contain issue context").Error())
	}

	labels := make([]string, 0, len(event.Issue.Labels))
	for _, l := range event.Issue.Labels {
		labels = append(labels, l.Name)
	}

	result := review.ReviewIssue(
		event.Issue.Number,
		event.Issue.Title,
		event.Issue.Body,
		labels,
	)

	cfg, err := policy.Load(*policyPath)
	if err != nil {
		fatal("failed to load policy: " + err.Error())
	}
	result = policy.Apply(cfg, result)

	if err := audit.Append(*auditPath, result); err != nil {
		fatal("failed to write audit log: " + err.Error())
	}
	writeJSON(*outputPath, result)
}

func enforceGate(args []string) {
	fs := flag.NewFlagSet("enforce", flag.ExitOnError)
	reviewPath := fs.String("review", "", "review JSON path")
	changedFilesPath := fs.String("changed-files", "", "changed files JSON path")
	rolloutPath := fs.String("rollout", "", "rollout policy JSON path")
	outputPath := fs.String("output", "", "output path for enforcement decision")
	failOnBlock := fs.Bool("fail-on-block", true, "exit non-zero when decision status is block")
	_ = fs.Parse(args)

	if *reviewPath == "" || *changedFilesPath == "" || *outputPath == "" {
		fatal("enforce requires --review, --changed-files, and --output")
	}

	reviewBytes, err := os.ReadFile(*reviewPath)
	if err != nil {
		fatal("failed to read review JSON: " + err.Error())
	}
	var result model.ReviewResult
	if err := json.Unmarshal(reviewBytes, &result); err != nil {
		fatal("failed to parse review JSON: " + err.Error())
	}

	changedBytes, err := os.ReadFile(*changedFilesPath)
	if err != nil {
		fatal("failed to read changed files JSON: " + err.Error())
	}
	var changedFiles []model.ChangedFile
	if err := json.Unmarshal(changedBytes, &changedFiles); err != nil {
		fatal("failed to parse changed files JSON: " + err.Error())
	}

	cfg, err := enforcement.Load(*rolloutPath)
	if err != nil {
		fatal("failed to load rollout policy: " + err.Error())
	}
	decision := enforcement.Decide(cfg, result, changedFiles)
	writeJSON(*outputPath, decision)

	if *failOnBlock && decision.Status == "block" {
		fatal("enforcement gate blocked: " + decision.Reason)
	}
}

func writeJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fatal(err.Error())
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		fatal(err.Error())
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
