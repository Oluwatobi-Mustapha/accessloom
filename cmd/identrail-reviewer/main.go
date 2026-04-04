package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/Oluwatobi-Mustapha/identrail/internal/identrailreviewer/model"
	"github.com/Oluwatobi-Mustapha/identrail/internal/identrailreviewer/review"
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: identrail-reviewer <review-pr|review-issue> [flags]")
	}

	switch os.Args[1] {
	case "review-pr":
		reviewPR(os.Args[2:])
	case "review-issue":
		reviewIssue(os.Args[2:])
	default:
		fatal("unknown subcommand: " + os.Args[1])
	}
}

func reviewPR(args []string) {
	fs := flag.NewFlagSet("review-pr", flag.ExitOnError)
	repoRoot := fs.String("repo-root", ".", "repository root")
	eventPath := fs.String("event-path", "", "GitHub event payload path")
	changedFilesPath := fs.String("changed-files", "", "changed files JSON path")
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
	writeJSON(*outputPath, result)
}

func reviewIssue(args []string) {
	fs := flag.NewFlagSet("review-issue", flag.ExitOnError)
	eventPath := fs.String("event-path", "", "GitHub event payload path")
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
	writeJSON(*outputPath, result)
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
