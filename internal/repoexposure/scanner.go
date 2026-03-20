package repoexposure

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
)

const (
	defaultHistoryLimit = 500
	defaultMaxFindings  = 200
	maxFileSizeBytes    = 1 << 20
)

var hunkHeaderPattern = regexp.MustCompile(`@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)

// CommandRunner executes git commands. It is injectable for deterministic tests.
type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Option customizes scanner behavior.
type Option func(*Scanner)

// Scanner detects secret exposure and misconfiguration findings in Git repositories.
type Scanner struct {
	run          CommandRunner
	now          func() time.Time
	historyLimit int
	maxFindings  int
}

// ScanResult summarizes one repository exposure scan.
type ScanResult struct {
	Repository     string           `json:"repository"`
	CommitsScanned int              `json:"commits_scanned"`
	FilesScanned   int              `json:"files_scanned"`
	Findings       []domain.Finding `json:"findings"`
	Truncated      bool             `json:"truncated"`
	StartedAt      time.Time        `json:"started_at"`
	CompletedAt    time.Time        `json:"completed_at"`
}

// NewScanner builds a repo exposure scanner with secure defaults.
func NewScanner(runner CommandRunner, options ...Option) *Scanner {
	if runner == nil {
		runner = defaultCommandRunner
	}
	s := &Scanner{
		run:          runner,
		now:          time.Now,
		historyLimit: defaultHistoryLimit,
		maxFindings:  defaultMaxFindings,
	}
	for _, option := range options {
		if option != nil {
			option(s)
		}
	}
	if s.historyLimit < 1 {
		s.historyLimit = defaultHistoryLimit
	}
	if s.maxFindings < 1 {
		s.maxFindings = defaultMaxFindings
	}
	return s
}

// WithHistoryLimit limits commit history depth for secret scanning.
func WithHistoryLimit(limit int) Option {
	return func(s *Scanner) {
		s.historyLimit = limit
	}
}

// WithMaxFindings caps finding volume per scan for deterministic output.
func WithMaxFindings(max int) Option {
	return func(s *Scanner) {
		s.maxFindings = max
	}
}

// WithNow overrides time source (tests only).
func WithNow(now func() time.Time) Option {
	return func(s *Scanner) {
		if now != nil {
			s.now = now
		}
	}
}

// ScanRepository performs read-only scanning for commit-history secret exposure and HEAD misconfigurations.
func (s *Scanner) ScanRepository(ctx context.Context, target string) (ScanResult, error) {
	repo := strings.TrimSpace(target)
	if repo == "" {
		return ScanResult{}, fmt.Errorf("repository target is required")
	}

	started := s.now().UTC()
	location, cleanup, err := s.prepareRepository(ctx, repo)
	if err != nil {
		return ScanResult{}, err
	}
	defer cleanup()

	commits, err := s.listCommits(ctx, location)
	if err != nil {
		return ScanResult{}, err
	}

	findings := make([]domain.Finding, 0, s.maxFindings)
	seen := map[string]struct{}{}
	truncated := false

	for _, commit := range commits {
		if err := ctx.Err(); err != nil {
			return ScanResult{}, err
		}
		patch, patchErr := s.git(ctx, location, "show", "--no-color", "--unified=0", "--format=", commit)
		if patchErr != nil {
			return ScanResult{}, fmt.Errorf("scan commit %s: %w", commit, patchErr)
		}
		for _, added := range parseAddedLines(patch) {
			secretFindings := detectSecretFindings(location.Display, commit, added.Path, added.Line, added.Text, started)
			for _, finding := range secretFindings {
				if _, exists := seen[finding.ID]; exists {
					continue
				}
				seen[finding.ID] = struct{}{}
				findings = append(findings, finding)
				if len(findings) >= s.maxFindings {
					truncated = true
					break
				}
			}
			if truncated {
				break
			}
		}
		if truncated {
			break
		}
	}

	filesScanned := 0
	if !truncated {
		headFiles, fileErr := s.listHeadFiles(ctx, location)
		if fileErr != nil {
			return ScanResult{}, fileErr
		}
		for _, filePath := range headFiles {
			if err := ctx.Err(); err != nil {
				return ScanResult{}, err
			}
			if !shouldInspectMisconfiguration(filePath) {
				continue
			}
			content, readErr := s.git(ctx, location, "show", "HEAD:"+filePath)
			if readErr != nil {
				return ScanResult{}, fmt.Errorf("read HEAD file %s: %w", filePath, readErr)
			}
			if len(content) == 0 || len(content) > maxFileSizeBytes || !utf8.Valid(content) {
				continue
			}
			filesScanned++
			for _, finding := range detectMisconfigFindings(location.Display, filePath, content, started) {
				if _, exists := seen[finding.ID]; exists {
					continue
				}
				seen[finding.ID] = struct{}{}
				findings = append(findings, finding)
				if len(findings) >= s.maxFindings {
					truncated = true
					break
				}
			}
			if truncated {
				break
			}
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity == findings[j].Severity {
			if findings[i].Type == findings[j].Type {
				return findings[i].ID < findings[j].ID
			}
			return findings[i].Type < findings[j].Type
		}
		return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
	})

	return ScanResult{
		Repository:     location.Display,
		CommitsScanned: len(commits),
		FilesScanned:   filesScanned,
		Findings:       findings,
		Truncated:      truncated,
		StartedAt:      started,
		CompletedAt:    s.now().UTC(),
	}, nil
}

type repositoryLocation struct {
	Path    string
	Bare    bool
	Display string
}

func (s *Scanner) prepareRepository(ctx context.Context, target string) (repositoryLocation, func(), error) {
	if local, ok := localRepository(target); ok {
		return local, func() {}, nil
	}

	cloneURL := normalizeRepositoryInput(target)
	if err := validateCloneURL(cloneURL); err != nil {
		return repositoryLocation{}, nil, err
	}
	workdir, err := os.MkdirTemp("", "identrail-repo-*")
	if err != nil {
		return repositoryLocation{}, nil, fmt.Errorf("create temp repository directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(workdir) }
	mirrorPath := filepath.Join(workdir, "repo.git")
	if _, runErr := s.run(ctx, "git", "clone", "--mirror", "--quiet", cloneURL, mirrorPath); runErr != nil {
		cleanup()
		return repositoryLocation{}, nil, fmt.Errorf("clone repository: %w", runErr)
	}
	return repositoryLocation{Path: mirrorPath, Bare: true, Display: target}, cleanup, nil
}

func (s *Scanner) listCommits(ctx context.Context, repo repositoryLocation) ([]string, error) {
	args := []string{"rev-list", "--all", "--max-count", strconv.Itoa(s.historyLimit)}
	output, err := s.git(ctx, repo, args...)
	if err != nil {
		return nil, fmt.Errorf("list commits: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	commits := make([]string, 0, len(lines))
	for _, line := range lines {
		sha := strings.TrimSpace(line)
		if sha == "" {
			continue
		}
		commits = append(commits, sha)
	}
	return commits, nil
}

func (s *Scanner) listHeadFiles(ctx context.Context, repo repositoryLocation) ([]string, error) {
	output, err := s.git(ctx, repo, "ls-tree", "-r", "--name-only", "HEAD")
	if err != nil {
		return nil, fmt.Errorf("list HEAD files: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	files := make([]string, 0, len(lines))
	for _, line := range lines {
		path := strings.TrimSpace(line)
		if path == "" {
			continue
		}
		files = append(files, path)
	}
	return files, nil
}

func (s *Scanner) git(ctx context.Context, repo repositoryLocation, args ...string) ([]byte, error) {
	if repo.Bare {
		invocation := append([]string{"--git-dir", repo.Path}, args...)
		output, err := s.run(ctx, "git", invocation...)
		if err != nil {
			return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
		}
		return output, nil
	}
	invocation := append([]string{"-C", repo.Path}, args...)
	output, err := s.run(ctx, "git", invocation...)
	if err != nil {
		return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return output, nil
}

type addedLine struct {
	Path string
	Line int
	Text string
}

func parseAddedLines(patch []byte) []addedLine {
	scanner := bufio.NewScanner(strings.NewReader(string(patch)))
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	lines := []addedLine{}

	currentPath := ""
	currentLine := 0
	inHunk := false

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "diff --git "):
			currentPath = parseDiffPath(line)
			currentLine = 0
			inHunk = false
		case strings.HasPrefix(line, "@@ "):
			match := hunkHeaderPattern.FindStringSubmatch(line)
			if len(match) != 2 {
				inHunk = false
				continue
			}
			parsed, err := strconv.Atoi(match[1])
			if err != nil || parsed < 1 {
				inHunk = false
				continue
			}
			currentLine = parsed
			inHunk = true
		default:
			if !inHunk {
				continue
			}
			if strings.HasPrefix(line, "+") {
				if strings.HasPrefix(line, "+++") {
					continue
				}
				if currentPath != "" && currentLine > 0 {
					lines = append(lines, addedLine{
						Path: currentPath,
						Line: currentLine,
						Text: strings.TrimSpace(strings.TrimPrefix(line, "+")),
					})
				}
				currentLine++
				continue
			}
			if strings.HasPrefix(line, " ") {
				currentLine++
				continue
			}
			if strings.HasPrefix(line, "-") || strings.HasPrefix(line, "\\") {
				continue
			}
		}
	}
	return lines
}

func parseDiffPath(line string) string {
	parts := strings.Fields(line)
	if len(parts) < 4 {
		return ""
	}
	path := strings.TrimSpace(parts[3])
	path = strings.Trim(path, "\"")
	return strings.TrimPrefix(path, "b/")
}

func localRepository(target string) (repositoryLocation, bool) {
	path := strings.TrimSpace(target)
	if path == "" {
		return repositoryLocation{}, false
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return repositoryLocation{}, false
	}
	if _, err := os.Stat(filepath.Join(path, ".git")); err == nil {
		absolute, absErr := filepath.Abs(path)
		if absErr != nil {
			absolute = path
		}
		return repositoryLocation{Path: absolute, Bare: false, Display: absolute}, true
	}
	if _, err := os.Stat(filepath.Join(path, "HEAD")); err != nil {
		return repositoryLocation{}, false
	}
	if _, err := os.Stat(filepath.Join(path, "objects")); err != nil {
		return repositoryLocation{}, false
	}
	absolute, absErr := filepath.Abs(path)
	if absErr != nil {
		absolute = path
	}
	return repositoryLocation{Path: absolute, Bare: true, Display: absolute}, true
}

func normalizeRepositoryInput(target string) string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return trimmed
	}
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") || strings.HasPrefix(trimmed, "git@") || strings.HasPrefix(trimmed, "ssh://") {
		return trimmed
	}
	if strings.Count(trimmed, "/") == 1 && !strings.Contains(trimmed, " ") {
		return "https://github.com/" + strings.TrimSuffix(trimmed, ".git") + ".git"
	}
	return trimmed
}

func validateCloneURL(cloneURL string) error {
	trimmed := strings.TrimSpace(cloneURL)
	if trimmed == "" {
		return fmt.Errorf("repository target is required")
	}

	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "http://") {
		return fmt.Errorf("insecure repository url scheme http is not allowed; use https or ssh")
	}
	if !strings.Contains(lower, "://") {
		return nil
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("parse repository target: %w", err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https", "ssh":
		return nil
	default:
		return fmt.Errorf("unsupported repository url scheme %q", parsed.Scheme)
	}
}

func redactMatch(line string, value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return line
	}
	return strings.ReplaceAll(line, trimmed, redactedToken(trimmed))
}

func redactedToken(value string) string {
	if len(value) <= 8 {
		return "[REDACTED]"
	}
	return fmt.Sprintf("[REDACTED:%s...%s]", value[:4], value[len(value)-4:])
}

func hashSHA1(parts ...string) string {
	h := sha1.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte("|"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func hashSHA256(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func severityRank(severity domain.FindingSeverity) int {
	switch severity {
	case domain.SeverityCritical:
		return 0
	case domain.SeverityHigh:
		return 1
	case domain.SeverityMedium:
		return 2
	case domain.SeverityLow:
		return 3
	default:
		return 4
	}
}

func defaultCommandRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}
