package review

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func readFile(repoRoot, relPath string) (string, error) {
	b, err := os.ReadFile(filepath.Join(repoRoot, relPath))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func lineOfSubstring(content, needle string) int {
	if needle == "" {
		return 1
	}
	s := bufio.NewScanner(strings.NewReader(content))
	line := 1
	for s.Scan() {
		if strings.Contains(s.Text(), needle) {
			return line
		}
		line++
	}
	return 1
}

func lineOfRegex(content string, re *regexp.Regexp) int {
	s := bufio.NewScanner(strings.NewReader(content))
	line := 1
	for s.Scan() {
		if re.MatchString(s.Text()) {
			return line
		}
		line++
	}
	return 1
}

func hasHeading(body, heading string) bool {
	needle := "### " + strings.ToLower(strings.TrimSpace(heading))
	s := bufio.NewScanner(strings.NewReader(body))
	for s.Scan() {
		if strings.TrimSpace(strings.ToLower(s.Text())) == needle {
			return true
		}
	}
	return false
}

func hasLabel(labels []string, want string) bool {
	for _, label := range labels {
		if strings.EqualFold(label, want) {
			return true
		}
	}
	return false
}

func slugToken(s string) string {
	token := strings.ToLower(strings.TrimSpace(s))
	token = strings.ReplaceAll(token, " ", "-")
	token = strings.ReplaceAll(token, "/", "-")
	token = strings.ReplaceAll(token, "_", "-")
	return token
}
