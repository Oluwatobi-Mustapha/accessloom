package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/identrailreviewer/model"
)

type Entry struct {
	Timestamp       string `json:"timestamp"`
	Reviewer        string `json:"reviewer"`
	Version         string `json:"version"`
	Target          string `json:"target"`
	Number          int    `json:"number"`
	Status          string `json:"status"`
	FindingCount    int    `json:"finding_count"`
	AbstentionCount int    `json:"abstention_count"`
	PolicyVersion   string `json:"policy_version,omitempty"`
	Fingerprint     string `json:"fingerprint"`
}

func Append(path string, result model.ReviewResult) error {
	if path == "" {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create audit directory: %w", err)
	}

	fingerprint, err := findingFingerprint(result.Findings)
	if err != nil {
		return fmt.Errorf("calculate fingerprint: %w", err)
	}

	entry := Entry{
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		Reviewer:        result.Reviewer,
		Version:         result.Version,
		Target:          result.Target,
		Number:          result.Number,
		Status:          result.Status,
		FindingCount:    len(result.Findings),
		AbstentionCount: len(result.Abstain),
		Fingerprint:     fingerprint,
	}
	if result.Metadata != nil {
		entry.PolicyVersion = result.Metadata["policy_version"]
	}

	b, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open audit file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("write audit entry: %w", err)
	}

	return nil
}

func findingFingerprint(findings []model.Finding) (string, error) {
	b, err := json.Marshal(findings)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
