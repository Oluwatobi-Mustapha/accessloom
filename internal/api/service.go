package api

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/app"
	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	"github.com/Oluwatobi-Mustapha/identrail/internal/domain"
	"github.com/Oluwatobi-Mustapha/identrail/internal/findings/standards"
	"github.com/Oluwatobi-Mustapha/identrail/internal/providers"
	"github.com/Oluwatobi-Mustapha/identrail/internal/repoexposure"
	"github.com/Oluwatobi-Mustapha/identrail/internal/scheduler"
)

const (
	defaultRepoScanHistoryLimit = 500
	defaultRepoScanMaxFindings  = 200
	defaultRepoScanHistoryMax   = 5000
	defaultRepoScanFindingsMax  = 1000
	defaultScanQueueMaxPending  = 25
	defaultRepoQueueMaxPending  = 100
	maxSourceErrorsInEvent      = 25
)

const (
	scanLifecycleQueued    = "queued"
	scanLifecycleRunning   = "running"
	scanLifecyclePartial   = "partial"
	scanLifecycleSucceeded = "succeeded"
	scanLifecycleFailed    = "failed"
)

// ScannerRunner is the scan execution dependency required by API service.
type ScannerRunner interface {
	Run(ctx context.Context) (app.ScanResult, error)
}

// RepoScanExecutor defines repository exposure scanning behavior.
type RepoScanExecutor interface {
	ScanRepository(ctx context.Context, target string) (repoexposure.ScanResult, error)
}

// RepoScannerFactory creates a repository scanner with bounded scan parameters.
type RepoScannerFactory func(historyLimit int, maxFindings int) RepoScanExecutor

// Service orchestrates scan execution and persistence.
type Service struct {
	Store          db.Store
	Scanner        ScannerRunner
	Provider       string
	DefaultScope   db.Scope
	Now            func() time.Time
	Locker         scheduler.Locker
	LockNamespace  string
	Alerter        FindingAlerter
	OnAlertError   func(error)
	ReadinessCheck func(context.Context) error
	// Repo scan controls are intentionally separate from cloud identity scan flow.
	RepoScanEnabled             bool
	RepoScanDefaultHistoryLimit int
	RepoScanDefaultMaxFindings  int
	RepoScanMaxHistoryLimit     int
	RepoScanMaxFindingsLimit    int
	RepoScanAllowedTargets      []string
	ScanQueueMaxPending         int
	RepoQueueMaxPending         int
	RepoScannerFactory          RepoScannerFactory
}

// CheckReadiness validates critical runtime dependencies for readiness checks.
func (s *Service) CheckReadiness(ctx context.Context) error {
	if s == nil {
		return errors.New("service is not initialized")
	}
	if s.Store == nil {
		return errors.New("store is not initialized")
	}
	if s.Scanner == nil {
		return errors.New("scanner is not initialized")
	}
	if s.ReadinessCheck != nil {
		if err := s.ReadinessCheck(ctx); err != nil {
			return err
		}
	}
	return nil
}

// RunScanResult is returned after a scan API trigger.
type RunScanResult struct {
	Scan             db.ScanRecord `json:"scan"`
	Assets           int           `json:"assets"`
	FindingCount     int           `json:"finding_count"`
	PartialSourceRun bool          `json:"partial_source_run"`
}

// RunRepoScanResult is returned after repo scan API trigger.
type RunRepoScanResult struct {
	RepoScan db.RepoScanRecord       `json:"repo_scan"`
	Result   repoexposure.ScanResult `json:"result"`
}

// RepoScanRequest captures one repository exposure scan request.
type RepoScanRequest struct {
	Repository   string `json:"repository"`
	HistoryLimit int    `json:"history_limit"`
	MaxFindings  int    `json:"max_findings"`
}

// FindingsFilter narrows findings list queries without changing API response schema.
type FindingsFilter struct {
	ScanID          string
	Severity        string
	Type            string
	LifecycleStatus string
	Assignee        string
}

// FindingTriageRequest captures one triage mutation request for a finding.
type FindingTriageRequest struct {
	Status               *string `json:"status,omitempty"`
	Assignee             *string `json:"assignee,omitempty"`
	SuppressionExpiresAt *string `json:"suppression_expires_at,omitempty"`
	Comment              string  `json:"comment,omitempty"`
}

// FindingsSummary returns quick aggregation counters for dashboards/alerts.
type FindingsSummary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByType     map[string]int `json:"by_type"`
}

// ScanDiff captures delta between one scan and its previous scan for same provider.
type ScanDiff struct {
	ScanID          string           `json:"scan_id"`
	PreviousScanID  string           `json:"previous_scan_id,omitempty"`
	AddedCount      int              `json:"added_count"`
	ResolvedCount   int              `json:"resolved_count"`
	PersistingCount int              `json:"persisting_count"`
	Added           []domain.Finding `json:"added"`
	Resolved        []domain.Finding `json:"resolved"`
	Persisting      []domain.Finding `json:"persisting"`
}

// TrendPoint gives one scan-level snapshot used by dashboard trend charts.
type TrendPoint struct {
	ScanID     string         `json:"scan_id"`
	StartedAt  time.Time      `json:"started_at"`
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
}

// FindingExports returns standards-aligned payloads for one finding.
type FindingExports struct {
	OCSF map[string]any `json:"ocsf"`
	ASFF map[string]any `json:"asff"`
}

// OwnershipFilter narrows ownership-signal query scope.
type OwnershipFilter struct {
	ScanID string
}

// ErrScanInProgress is returned when a scan for the same provider is already running.
var ErrScanInProgress = errors.New("scan already in progress")

// ErrScanQueueFull is returned when queued scan requests exceed configured capacity.
var ErrScanQueueFull = errors.New("scan queue is full")

// ErrInvalidScanDiffBaseline is returned when previous_scan_id is incompatible.
var ErrInvalidScanDiffBaseline = errors.New("invalid scan diff baseline")

// ErrRepoScanDisabled is returned when repository exposure scanning is disabled.
var ErrRepoScanDisabled = errors.New("repo scan is disabled")

// ErrRepoTargetNotAllowed is returned when repository target is outside configured allowlist.
var ErrRepoTargetNotAllowed = errors.New("repo target is not allowed")

// ErrInvalidRepoScanRequest indicates invalid repository scan request input.
var ErrInvalidRepoScanRequest = errors.New("invalid repo scan request")

// ErrRepoScanInProgress is returned when the same repository scan target is already running.
var ErrRepoScanInProgress = errors.New("repo scan already in progress")

// ErrInvalidFindingTriageRequest indicates invalid triage payload or state transition.
var ErrInvalidFindingTriageRequest = errors.New("invalid finding triage request")

// ErrRepoScanQueueFull is returned when queued repo scan requests exceed configured capacity.
var ErrRepoScanQueueFull = errors.New("repo scan queue is full")

// NewService creates an API service with defaults.
func NewService(store db.Store, scanner ScannerRunner, provider string) *Service {
	return &Service{
		Store:                       store,
		Scanner:                     scanner,
		Provider:                    provider,
		DefaultScope:                db.Scope{}.Normalize(),
		Now:                         time.Now,
		Locker:                      scheduler.NewInMemoryLocker(),
		LockNamespace:               "identrail",
		Alerter:                     NopFindingAlerter{},
		RepoScanEnabled:             true,
		RepoScanDefaultHistoryLimit: defaultRepoScanHistoryLimit,
		RepoScanDefaultMaxFindings:  defaultRepoScanMaxFindings,
		RepoScanMaxHistoryLimit:     defaultRepoScanHistoryMax,
		RepoScanMaxFindingsLimit:    defaultRepoScanFindingsMax,
		ScanQueueMaxPending:         defaultScanQueueMaxPending,
		RepoQueueMaxPending:         defaultRepoQueueMaxPending,
		RepoScannerFactory: func(historyLimit int, maxFindings int) RepoScanExecutor {
			return repoexposure.NewScanner(
				nil,
				repoexposure.WithHistoryLimit(historyLimit),
				repoexposure.WithMaxFindings(maxFindings),
			)
		},
	}
}

// EnqueueScan stores one queued scan request for asynchronous worker execution.
func (s *Service) EnqueueScan(ctx context.Context) (db.ScanRecord, error) {
	ctx = s.scopeContext(ctx)
	maxPending := s.ScanQueueMaxPending
	if maxPending <= 0 {
		maxPending = defaultScanQueueMaxPending
	}
	queuedCount, err := s.Store.CountQueuedScans(ctx, s.Provider)
	if err != nil {
		return db.ScanRecord{}, fmt.Errorf("count queued scans: %w", err)
	}
	if queuedCount >= maxPending {
		return db.ScanRecord{}, ErrScanQueueFull
	}
	record, err := s.Store.CreateQueuedScan(ctx, s.Provider, s.Now().UTC())
	if err != nil {
		return db.ScanRecord{}, fmt.Errorf("enqueue scan: %w", err)
	}
	s.appendScanLifecycleEvent(ctx, record.ID, scanLifecycleQueued, map[string]any{"provider": s.Provider})
	s.appendScanEvent(ctx, record.ID, db.ScanEventLevelInfo, "scan queued for worker execution", map[string]any{
		"provider":    s.Provider,
		"queue_depth": queuedCount + 1,
		"queue_limit": maxPending,
	})
	return record, nil
}

// ProcessNextQueuedScan claims and executes one queued scan. It returns false when no job is available.
func (s *Service) ProcessNextQueuedScan(ctx context.Context) (bool, error) {
	ctx = s.scopeContext(ctx)
	if s.Locker != nil {
		release, ok := s.Locker.TryAcquire(s.lockKey("scan:" + s.Provider))
		if !ok {
			return false, nil
		}
		defer release()
	}
	record, err := s.Store.ClaimNextQueuedScan(ctx, s.Provider)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("claim queued scan: %w", err)
	}
	s.appendScanLifecycleEvent(ctx, record.ID, scanLifecycleRunning, map[string]any{"provider": record.Provider})
	s.appendScanEvent(ctx, record.ID, db.ScanEventLevelInfo, "queued scan started", map[string]any{"provider": record.Provider})
	_, runErr := s.runScanWithRecord(ctx, record)
	if runErr != nil {
		return true, runErr
	}
	return true, nil
}

// RunScan executes one scan and persists metadata + findings.
func (s *Service) RunScan(ctx context.Context) (RunScanResult, error) {
	ctx = s.scopeContext(ctx)
	if s.Locker != nil {
		release, ok := s.Locker.TryAcquire(s.lockKey("scan:" + s.Provider))
		if !ok {
			return RunScanResult{}, ErrScanInProgress
		}
		defer release()
	}
	record, err := s.Store.CreateScan(ctx, s.Provider, s.Now().UTC())
	if err != nil {
		return RunScanResult{}, err
	}
	s.appendScanLifecycleEvent(ctx, record.ID, scanLifecycleQueued, map[string]any{"provider": s.Provider})
	s.appendScanLifecycleEvent(ctx, record.ID, scanLifecycleRunning, map[string]any{"provider": s.Provider})
	s.appendScanEvent(ctx, record.ID, db.ScanEventLevelInfo, "scan started", map[string]any{"provider": s.Provider})
	return s.runScanWithRecord(ctx, record)
}

func (s *Service) runScanWithRecord(ctx context.Context, record db.ScanRecord) (RunScanResult, error) {
	ctx = s.scopeContext(ctx)
	result, err := s.Scanner.Run(ctx)
	if err != nil {
		s.appendScanLifecycleEvent(ctx, record.ID, scanLifecycleFailed, map[string]any{"error": err.Error()})
		s.appendScanEvent(ctx, record.ID, db.ScanEventLevelError, "scan failed during collection/analysis", map[string]any{"error": err.Error()})
		_ = s.Store.CompleteScan(ctx, record.ID, "failed", s.Now().UTC(), 0, 0, err.Error())
		return RunScanResult{}, err
	}
	result.Findings = enrichFindings(result.Findings)
	if len(result.SourceErrors) > 0 {
		s.appendScanEvent(ctx, record.ID, db.ScanEventLevelWarn, "scan completed with partial source errors", map[string]any{
			"source_error_count": len(result.SourceErrors),
			"source_errors":      truncateSourceErrors(result.SourceErrors, maxSourceErrorsInEvent),
		})
		s.appendScanLifecycleEvent(ctx, record.ID, scanLifecyclePartial, map[string]any{"source_error_count": len(result.SourceErrors)})
	}

	if err := s.Store.UpsertArtifacts(ctx, record.ID, db.ScanArtifacts{
		RawAssets:     result.RawAssets,
		Bundle:        result.Bundle,
		Permissions:   result.Permissions,
		Relationships: result.Relationships,
	}); err != nil {
		s.appendScanLifecycleEvent(ctx, record.ID, scanLifecycleFailed, map[string]any{"error": err.Error()})
		s.appendScanEvent(ctx, record.ID, db.ScanEventLevelError, "scan failed while persisting artifacts", map[string]any{"error": err.Error()})
		_ = s.Store.CompleteScan(ctx, record.ID, "failed", s.Now().UTC(), result.Assets, 0, err.Error())
		return RunScanResult{}, fmt.Errorf("persist artifacts: %w", err)
	}
	s.appendScanEvent(ctx, record.ID, db.ScanEventLevelInfo, "artifacts persisted", map[string]any{"raw_assets": len(result.RawAssets), "identities": len(result.Bundle.Identities)})

	if err := s.Store.UpsertFindings(ctx, record.ID, result.Findings); err != nil {
		s.appendScanLifecycleEvent(ctx, record.ID, scanLifecycleFailed, map[string]any{"error": err.Error()})
		s.appendScanEvent(ctx, record.ID, db.ScanEventLevelError, "scan failed while persisting findings", map[string]any{"error": err.Error()})
		_ = s.Store.CompleteScan(ctx, record.ID, "failed", s.Now().UTC(), result.Assets, 0, err.Error())
		return RunScanResult{}, fmt.Errorf("persist findings: %w", err)
	}
	s.appendScanEvent(ctx, record.ID, db.ScanEventLevelInfo, "findings persisted", map[string]any{"findings": len(result.Findings)})

	if err := s.Store.CompleteScan(ctx, record.ID, "completed", s.Now().UTC(), result.Assets, len(result.Findings), ""); err != nil {
		s.appendScanLifecycleEvent(ctx, record.ID, scanLifecycleFailed, map[string]any{"error": err.Error()})
		s.appendScanEvent(ctx, record.ID, db.ScanEventLevelError, "scan failed while finalizing scan record", map[string]any{"error": err.Error()})
		return RunScanResult{}, fmt.Errorf("complete scan record: %w", err)
	}

	record.Status = "completed"
	finished := s.Now().UTC()
	record.FinishedAt = &finished
	record.AssetCount = result.Assets
	record.FindingCount = len(result.Findings)
	s.appendScanLifecycleEvent(ctx, record.ID, scanLifecycleSucceeded, map[string]any{
		"assets":             result.Assets,
		"findings":           len(result.Findings),
		"partial_source_run": len(result.SourceErrors) > 0,
	})
	s.appendScanEvent(ctx, record.ID, db.ScanEventLevelInfo, "scan completed", map[string]any{"assets": result.Assets, "findings": len(result.Findings)})
	provider := strings.TrimSpace(record.Provider)
	if provider == "" {
		provider = s.Provider
	}
	if s.Alerter != nil {
		if alertErr := s.Alerter.NotifyScan(ctx, provider, record, result.Findings); alertErr != nil && s.OnAlertError != nil {
			s.OnAlertError(alertErr)
		}
	}

	return RunScanResult{
		Scan:             record,
		Assets:           result.Assets,
		FindingCount:     len(result.Findings),
		PartialSourceRun: len(result.SourceErrors) > 0,
	}, nil
}

// ListFindings returns persisted findings.
func (s *Service) ListFindings(ctx context.Context, limit int) ([]domain.Finding, error) {
	ctx = s.scopeContext(ctx)
	items, err := s.Store.ListFindings(ctx, limit)
	if err != nil {
		return nil, err
	}
	enriched := enrichFindings(items)
	return s.applyFindingTriageStates(ctx, enriched)
}

// RunRepoScan performs one repository exposure scan with configured guardrails.
func (s *Service) RunRepoScan(ctx context.Context, request RepoScanRequest) (repoexposure.ScanResult, error) {
	runResult, err := s.RunRepoScanPersisted(ctx, request)
	if err != nil {
		return repoexposure.ScanResult{}, err
	}
	return runResult.Result, nil
}

// EnqueueRepoScan stores one queued repository scan request for asynchronous worker execution.
func (s *Service) EnqueueRepoScan(ctx context.Context, request RepoScanRequest) (db.RepoScanRecord, error) {
	ctx = s.scopeContext(ctx)
	target, historyLimit, maxFindings, err := s.validateRepoScanRequest(request)
	if err != nil {
		return db.RepoScanRecord{}, err
	}
	pendingForTarget, err := s.Store.CountPendingRepoScansByRepository(ctx, target)
	if err != nil {
		return db.RepoScanRecord{}, fmt.Errorf("count pending repo scans for target: %w", err)
	}
	if pendingForTarget > 0 {
		return db.RepoScanRecord{}, ErrRepoScanInProgress
	}
	maxPending := s.RepoQueueMaxPending
	if maxPending <= 0 {
		maxPending = defaultRepoQueueMaxPending
	}
	queuedCount, err := s.Store.CountQueuedRepoScans(ctx)
	if err != nil {
		return db.RepoScanRecord{}, fmt.Errorf("count queued repo scans: %w", err)
	}
	if queuedCount >= maxPending {
		return db.RepoScanRecord{}, ErrRepoScanQueueFull
	}
	record, err := s.Store.CreateQueuedRepoScan(ctx, target, historyLimit, maxFindings, s.Now().UTC())
	if err != nil {
		return db.RepoScanRecord{}, fmt.Errorf("enqueue repo scan: %w", err)
	}
	return record, nil
}

// ProcessNextQueuedRepoScan claims and executes one queued repository scan. It returns false when no job is available.
func (s *Service) ProcessNextQueuedRepoScan(ctx context.Context) (bool, error) {
	ctx = s.scopeContext(ctx)
	record, err := s.Store.ClaimNextQueuedRepoScan(ctx)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("claim queued repo scan: %w", err)
	}
	requeue := false
	if s.Locker != nil {
		release, ok := s.Locker.TryAcquire(s.lockKey("repo-scan:" + strings.ToLower(record.Repository)))
		if !ok {
			requeue = true
		} else {
			defer release()
		}
	}
	if requeue {
		if requeueErr := s.Store.RequeueRepoScan(ctx, record.ID); requeueErr != nil && !errors.Is(requeueErr, db.ErrNotFound) {
			return false, fmt.Errorf("requeue repo scan: %w", requeueErr)
		}
		// A queued item was handled (requeued) even if this target is currently locked.
		// Returning true lets the worker keep draining other queued targets in the same tick.
		return true, nil
	}
	_, runErr := s.runRepoScanWithRecord(ctx, record, record.HistoryLimit, record.MaxFindings)
	if runErr != nil {
		return true, runErr
	}
	return true, nil
}

// RunRepoScanPersisted runs one repository scan and persists repo scan metadata + findings.
func (s *Service) RunRepoScanPersisted(ctx context.Context, request RepoScanRequest) (RunRepoScanResult, error) {
	ctx = s.scopeContext(ctx)
	target, historyLimit, maxFindings, err := s.validateRepoScanRequest(request)
	if err != nil {
		return RunRepoScanResult{}, err
	}
	if s.Locker != nil {
		release, ok := s.Locker.TryAcquire(s.lockKey("repo-scan:" + strings.ToLower(target)))
		if !ok {
			return RunRepoScanResult{}, ErrRepoScanInProgress
		}
		defer release()
	}
	record, err := s.Store.CreateRepoScan(ctx, target, s.Now().UTC())
	if err != nil {
		return RunRepoScanResult{}, fmt.Errorf("create repo scan: %w", err)
	}
	return s.runRepoScanWithRecord(ctx, record, historyLimit, maxFindings)
}

func (s *Service) validateRepoScanRequest(request RepoScanRequest) (string, int, int, error) {
	if !s.RepoScanEnabled {
		return "", 0, 0, ErrRepoScanDisabled
	}
	target := strings.TrimSpace(request.Repository)
	if target == "" {
		return "", 0, 0, ErrInvalidRepoScanRequest
	}
	if repoexposure.IsLocalRepositoryTarget(target) {
		return "", 0, 0, ErrRepoTargetNotAllowed
	}
	if !repoTargetAllowed(target, s.RepoScanAllowedTargets) {
		return "", 0, 0, ErrRepoTargetNotAllowed
	}
	historyLimit, err := sanitizeRepoScanLimit(request.HistoryLimit, s.RepoScanDefaultHistoryLimit, s.RepoScanMaxHistoryLimit)
	if err != nil {
		return "", 0, 0, ErrInvalidRepoScanRequest
	}
	maxFindings, err := sanitizeRepoScanLimit(request.MaxFindings, s.RepoScanDefaultMaxFindings, s.RepoScanMaxFindingsLimit)
	if err != nil {
		return "", 0, 0, ErrInvalidRepoScanRequest
	}
	return target, historyLimit, maxFindings, nil
}

func (s *Service) runRepoScanWithRecord(ctx context.Context, record db.RepoScanRecord, historyLimit int, maxFindings int) (RunRepoScanResult, error) {
	ctx = s.scopeContext(ctx)
	target := strings.TrimSpace(record.Repository)
	if target == "" {
		return RunRepoScanResult{}, ErrInvalidRepoScanRequest
	}
	normalizedHistory, err := sanitizeRepoScanLimit(historyLimit, s.RepoScanDefaultHistoryLimit, s.RepoScanMaxHistoryLimit)
	if err != nil {
		_ = s.Store.CompleteRepoScan(ctx, record.ID, "failed", s.Now().UTC(), 0, 0, 0, false, ErrInvalidRepoScanRequest.Error())
		return RunRepoScanResult{}, ErrInvalidRepoScanRequest
	}
	normalizedMaxFindings, err := sanitizeRepoScanLimit(maxFindings, s.RepoScanDefaultMaxFindings, s.RepoScanMaxFindingsLimit)
	if err != nil {
		_ = s.Store.CompleteRepoScan(ctx, record.ID, "failed", s.Now().UTC(), 0, 0, 0, false, ErrInvalidRepoScanRequest.Error())
		return RunRepoScanResult{}, ErrInvalidRepoScanRequest
	}
	if s.RepoScannerFactory == nil {
		return RunRepoScanResult{}, fmt.Errorf("repo scanner factory is not configured")
	}
	result, err := s.RepoScannerFactory(normalizedHistory, normalizedMaxFindings).ScanRepository(ctx, target)
	if err != nil {
		_ = s.Store.CompleteRepoScan(ctx, record.ID, "failed", s.Now().UTC(), 0, 0, 0, false, err.Error())
		return RunRepoScanResult{}, err
	}
	result.Findings = enrichFindings(result.Findings)
	if err := s.Store.UpsertRepoFindings(ctx, record.ID, result.Findings); err != nil {
		_ = s.Store.CompleteRepoScan(ctx, record.ID, "failed", s.Now().UTC(), result.CommitsScanned, result.FilesScanned, 0, result.Truncated, err.Error())
		return RunRepoScanResult{}, fmt.Errorf("persist repo findings: %w", err)
	}
	if err := s.Store.CompleteRepoScan(
		ctx,
		record.ID,
		"completed",
		s.Now().UTC(),
		result.CommitsScanned,
		result.FilesScanned,
		len(result.Findings),
		result.Truncated,
		"",
	); err != nil {
		return RunRepoScanResult{}, fmt.Errorf("complete repo scan: %w", err)
	}
	record.Status = "completed"
	finished := s.Now().UTC()
	record.FinishedAt = &finished
	record.CommitsScanned = result.CommitsScanned
	record.FilesScanned = result.FilesScanned
	record.FindingCount = len(result.Findings)
	record.Truncated = result.Truncated
	record.HistoryLimit = normalizedHistory
	record.MaxFindings = normalizedMaxFindings
	return RunRepoScanResult{RepoScan: record, Result: result}, nil
}

// ListRepoScans returns persisted repository scans.
func (s *Service) ListRepoScans(ctx context.Context, limit int) ([]db.RepoScanRecord, error) {
	ctx = s.scopeContext(ctx)
	return s.Store.ListRepoScans(ctx, limit)
}

// GetRepoScan returns one repository scan by id.
func (s *Service) GetRepoScan(ctx context.Context, repoScanID string) (db.RepoScanRecord, error) {
	ctx = s.scopeContext(ctx)
	id := strings.TrimSpace(repoScanID)
	if id == "" {
		return db.RepoScanRecord{}, db.ErrNotFound
	}
	return s.Store.GetRepoScan(ctx, id)
}

// ListRepoFindings returns repository findings using optional filters.
func (s *Service) ListRepoFindings(ctx context.Context, limit int, filter db.RepoFindingFilter) ([]domain.Finding, error) {
	ctx = s.scopeContext(ctx)
	findings, err := s.Store.ListRepoFindings(ctx, filter, limit)
	if err != nil {
		return nil, err
	}
	return enrichFindings(findings), nil
}

// ListFindingsFiltered returns findings with optional scan/type/severity filters.
func (s *Service) ListFindingsFiltered(ctx context.Context, limit int, filter FindingsFilter) ([]domain.Finding, error) {
	ctx = s.scopeContext(ctx)
	loadLimit := limit
	if loadLimit <= 0 {
		loadLimit = 100
	}
	if loadLimit < 5000 {
		loadLimit = 5000
	}

	var source []domain.Finding
	var err error
	if strings.TrimSpace(filter.ScanID) != "" {
		source, err = s.Store.ListFindingsByScan(ctx, strings.TrimSpace(filter.ScanID), loadLimit)
	} else {
		source, err = s.Store.ListFindings(ctx, loadLimit)
	}
	if err != nil {
		return nil, err
	}

	severity := strings.ToLower(strings.TrimSpace(filter.Severity))
	findingType := strings.ToLower(strings.TrimSpace(filter.Type))
	lifecycleStatus := strings.ToLower(strings.TrimSpace(filter.LifecycleStatus))
	assignee := strings.ToLower(strings.TrimSpace(filter.Assignee))
	result := make([]domain.Finding, 0, len(source))
	for _, item := range source {
		if severity != "" && strings.ToLower(string(item.Severity)) != severity {
			continue
		}
		if findingType != "" && strings.ToLower(string(item.Type)) != findingType {
			continue
		}
		result = append(result, item)
	}
	enriched := enrichFindings(result)
	withTriage, err := s.applyFindingTriageStates(ctx, enriched)
	if err != nil {
		return nil, err
	}

	filtered := make([]domain.Finding, 0, len(withTriage))
	for _, item := range withTriage {
		if lifecycleStatus != "" && strings.ToLower(string(item.Triage.Status)) != lifecycleStatus {
			continue
		}
		if assignee != "" && strings.ToLower(strings.TrimSpace(item.Triage.Assignee)) != assignee {
			continue
		}
		filtered = append(filtered, item)
		if limit > 0 && len(filtered) >= limit {
			break
		}
	}
	return filtered, nil
}

// GetFinding returns one finding by id, optionally scoped to one scan.
func (s *Service) GetFinding(ctx context.Context, findingID string, scanID string) (domain.Finding, error) {
	id := strings.TrimSpace(findingID)
	if id == "" {
		return domain.Finding{}, db.ErrNotFound
	}
	filtered, err := s.ListFindingsFiltered(ctx, 5000, FindingsFilter{ScanID: strings.TrimSpace(scanID)})
	if err != nil {
		return domain.Finding{}, err
	}
	for _, item := range filtered {
		if item.ID == id {
			return item, nil
		}
	}
	return domain.Finding{}, db.ErrNotFound
}

// TriageFinding applies one workflow mutation and records audit history.
func (s *Service) TriageFinding(ctx context.Context, findingID string, scanID string, request FindingTriageRequest, actor string) (domain.Finding, error) {
	id := strings.TrimSpace(findingID)
	if id == "" {
		return domain.Finding{}, db.ErrNotFound
	}
	if _, err := s.GetFinding(ctx, id, scanID); err != nil {
		return domain.Finding{}, err
	}
	if request.Status == nil && request.Assignee == nil && request.SuppressionExpiresAt == nil && strings.TrimSpace(request.Comment) == "" {
		return domain.Finding{}, ErrInvalidFindingTriageRequest
	}

	now := s.Now().UTC()
	currentState, err := s.Store.GetFindingTriageState(ctx, id)
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		return domain.Finding{}, err
	}
	if errors.Is(err, db.ErrNotFound) {
		currentState = db.FindingTriageState{
			FindingID: id,
			Status:    domain.FindingLifecycleOpen,
		}
	}
	currentState = normalizeFindingTriageState(currentState, now)
	nextState := currentState
	changed := false

	if request.Status != nil {
		parsedStatus, parseErr := parseFindingLifecycleStatus(*request.Status)
		if parseErr != nil {
			return domain.Finding{}, parseErr
		}
		if nextState.Status != parsedStatus {
			changed = true
		}
		nextState.Status = parsedStatus
	}
	if request.Assignee != nil {
		nextAssignee := strings.TrimSpace(*request.Assignee)
		if nextState.Assignee != nextAssignee {
			changed = true
		}
		nextState.Assignee = nextAssignee
	}
	if request.SuppressionExpiresAt != nil {
		parsedExpiry, parseErr := parseSuppressionExpiry(*request.SuppressionExpiresAt, now)
		if parseErr != nil {
			return domain.Finding{}, parseErr
		}
		if !timePointersEqual(nextState.SuppressionExpiresAt, parsedExpiry) {
			changed = true
		}
		nextState.SuppressionExpiresAt = parsedExpiry
	}
	if nextState.Status != domain.FindingLifecycleSuppressed && nextState.SuppressionExpiresAt != nil {
		nextState.SuppressionExpiresAt = nil
		changed = true
	}
	if nextState.Status == domain.FindingLifecycleSuppressed && nextState.SuppressionExpiresAt != nil && !nextState.SuppressionExpiresAt.After(now) {
		return domain.Finding{}, ErrInvalidFindingTriageRequest
	}
	comment := strings.TrimSpace(request.Comment)
	if !changed && comment == "" {
		return domain.Finding{}, ErrInvalidFindingTriageRequest
	}

	nextState.FindingID = id
	nextState.UpdatedAt = now
	nextState.UpdatedBy = normalizeActor(actor)
	if nextState.Status == "" {
		nextState.Status = domain.FindingLifecycleOpen
	}

	action := deriveFindingTriageAction(currentState, nextState, comment)
	if err := s.Store.ApplyFindingTriageTransition(ctx, nextState, db.FindingTriageEvent{
		FindingID:            id,
		Action:               action,
		FromStatus:           currentState.Status,
		ToStatus:             nextState.Status,
		Assignee:             nextState.Assignee,
		SuppressionExpiresAt: nextState.SuppressionExpiresAt,
		Comment:              comment,
		Actor:                nextState.UpdatedBy,
		CreatedAt:            now,
	}); err != nil {
		return domain.Finding{}, err
	}

	return s.GetFinding(ctx, id, scanID)
}

// ListFindingTriageHistory returns triage actions newest-first for one finding.
func (s *Service) ListFindingTriageHistory(ctx context.Context, findingID string, scanID string, limit int) ([]db.FindingTriageEvent, error) {
	id := strings.TrimSpace(findingID)
	if id == "" {
		return nil, db.ErrNotFound
	}
	if _, err := s.GetFinding(ctx, id, scanID); err != nil {
		return nil, err
	}
	return s.Store.ListFindingTriageEvents(ctx, id, limit)
}

// GetFindingExports returns OCSF-aligned and ASFF payloads for one finding.
func (s *Service) GetFindingExports(ctx context.Context, findingID string, scanID string) (FindingExports, error) {
	finding, err := s.GetFinding(ctx, findingID, scanID)
	if err != nil {
		return FindingExports{}, err
	}
	return FindingExports{
		OCSF: standards.BuildOCSFAlignedExport(finding),
		ASFF: standards.BuildASFFExport(finding, "", "", ""),
	}, nil
}

// ListScans returns persisted scans.
func (s *Service) ListScans(ctx context.Context, limit int) ([]db.ScanRecord, error) {
	ctx = s.scopeContext(ctx)
	return s.Store.ListScans(ctx, limit)
}

// GetFindingsSummary returns grouped counts by severity and type.
func (s *Service) GetFindingsSummary(ctx context.Context, limit int) (FindingsSummary, error) {
	ctx = s.scopeContext(ctx)
	items, err := s.Store.ListFindings(ctx, limit)
	if err != nil {
		return FindingsSummary{}, err
	}
	summary := FindingsSummary{
		Total:      len(items),
		BySeverity: map[string]int{},
		ByType:     map[string]int{},
	}
	for _, item := range items {
		summary.BySeverity[string(item.Severity)]++
		summary.ByType[string(item.Type)]++
	}
	return summary, nil
}

// ListScanEvents returns recent scan events for one scan id.
func (s *Service) ListScanEvents(ctx context.Context, scanID string, limit int) ([]db.ScanEvent, error) {
	return s.ListScanEventsFiltered(ctx, scanID, "", limit)
}

// ListScanEventsFiltered returns recent scan events with optional level filtering.
func (s *Service) ListScanEventsFiltered(ctx context.Context, scanID string, level string, limit int) ([]db.ScanEvent, error) {
	ctx = s.scopeContext(ctx)
	events, err := s.Store.ListScanEvents(ctx, scanID, limit)
	if err != nil {
		return nil, err
	}
	normalizedLevel := strings.ToLower(strings.TrimSpace(level))
	if normalizedLevel == "" {
		return events, nil
	}
	result := make([]db.ScanEvent, 0, len(events))
	for _, event := range events {
		if strings.ToLower(strings.TrimSpace(event.Level)) != normalizedLevel {
			continue
		}
		result = append(result, event)
	}
	return result, nil
}

// ListIdentities returns identities for given filters, defaulting scan_id to latest scan.
func (s *Service) ListIdentities(ctx context.Context, scanID string, provider string, identityType string, namePrefix string, limit int) ([]domain.Identity, error) {
	ctx = s.scopeContext(ctx)
	normalizedScanID := scanID
	if normalizedScanID == "" {
		latest, err := s.latestScanID(ctx)
		if err != nil {
			return nil, err
		}
		normalizedScanID = latest
	}
	return s.Store.ListIdentities(ctx, db.IdentityFilter{
		ScanID:     normalizedScanID,
		Provider:   provider,
		Type:       identityType,
		NamePrefix: namePrefix,
	}, limit)
}

// ListRelationships returns relationships for given filters, defaulting scan_id to latest scan.
func (s *Service) ListRelationships(ctx context.Context, scanID string, relationshipType string, fromNodeID string, toNodeID string, limit int) ([]domain.Relationship, error) {
	ctx = s.scopeContext(ctx)
	normalizedScanID := scanID
	if normalizedScanID == "" {
		latest, err := s.latestScanID(ctx)
		if err != nil {
			return nil, err
		}
		normalizedScanID = latest
	}
	return s.Store.ListRelationships(ctx, db.RelationshipFilter{
		ScanID:     normalizedScanID,
		Type:       relationshipType,
		FromNodeID: fromNodeID,
		ToNodeID:   toNodeID,
	}, limit)
}

// GetFindingsTrend returns findings totals by severity across recent scans.
func (s *Service) GetFindingsTrend(ctx context.Context, points int) ([]TrendPoint, error) {
	return s.GetFindingsTrendFiltered(ctx, points, "", "")
}

// GetFindingsTrendFiltered returns findings trend with optional severity/type filters.
func (s *Service) GetFindingsTrendFiltered(ctx context.Context, points int, severity string, findingType string) ([]TrendPoint, error) {
	ctx = s.scopeContext(ctx)
	if points <= 0 {
		points = 10
	}
	scans, err := s.Store.ListScans(ctx, points)
	if err != nil {
		return nil, err
	}
	// Return oldest->newest for chart consumers.
	sort.Slice(scans, func(i, j int) bool { return scans[i].StartedAt.Before(scans[j].StartedAt) })
	result := make([]TrendPoint, 0, len(scans))
	normalizedSeverity := strings.ToLower(strings.TrimSpace(severity))
	normalizedType := strings.ToLower(strings.TrimSpace(findingType))
	for _, scan := range scans {
		findings, err := s.Store.ListFindingsByScan(ctx, scan.ID, 5000)
		if err != nil {
			if errors.Is(err, db.ErrNotFound) {
				continue
			}
			return nil, err
		}
		point := TrendPoint{
			ScanID:     scan.ID,
			StartedAt:  scan.StartedAt,
			BySeverity: map[string]int{},
		}
		for _, finding := range findings {
			if normalizedSeverity != "" && strings.ToLower(string(finding.Severity)) != normalizedSeverity {
				continue
			}
			if normalizedType != "" && strings.ToLower(string(finding.Type)) != normalizedType {
				continue
			}
			point.BySeverity[string(finding.Severity)]++
			point.Total++
		}
		result = append(result, point)
	}
	return result, nil
}

// ListOwnershipSignals returns inferred ownership hints for identities in one scan.
func (s *Service) ListOwnershipSignals(ctx context.Context, limit int, filter OwnershipFilter) ([]domain.OwnershipSignal, error) {
	ctx = s.scopeContext(ctx)
	normalizedScanID := strings.TrimSpace(filter.ScanID)
	if normalizedScanID == "" {
		latest, err := s.latestScanID(ctx)
		if err != nil {
			return nil, err
		}
		normalizedScanID = latest
	}
	loadLimit := limit
	if loadLimit <= 0 {
		loadLimit = 100
	}
	if loadLimit > 5000 {
		loadLimit = 5000
	}
	identities, err := s.Store.ListIdentities(ctx, db.IdentityFilter{ScanID: normalizedScanID}, loadLimit)
	if err != nil {
		return nil, err
	}
	signals := make([]domain.OwnershipSignal, 0, len(identities))
	for _, identity := range identities {
		signal, ok := inferOwnershipSignal(identity)
		if !ok {
			continue
		}
		signals = append(signals, signal)
	}
	sort.Slice(signals, func(i, j int) bool {
		if signals[i].Confidence == signals[j].Confidence {
			return signals[i].IdentityID < signals[j].IdentityID
		}
		return signals[i].Confidence > signals[j].Confidence
	})
	if limit > 0 && len(signals) > limit {
		signals = signals[:limit]
	}
	return signals, nil
}

// GetScanDiff compares findings between this scan and previous scan of same provider.
func (s *Service) GetScanDiff(ctx context.Context, scanID string, limit int) (ScanDiff, error) {
	return s.GetScanDiffAgainst(ctx, scanID, "", limit)
}

// GetScanDiffAgainst compares findings between one scan and an optional baseline scan.
func (s *Service) GetScanDiffAgainst(ctx context.Context, scanID string, previousScanID string, limit int) (ScanDiff, error) {
	ctx = s.scopeContext(ctx)
	currentScan, err := s.Store.GetScan(ctx, scanID)
	if err != nil {
		return ScanDiff{}, err
	}

	currentFindings, err := s.Store.ListFindingsByScan(ctx, scanID, 5000)
	if err != nil {
		return ScanDiff{}, err
	}
	normalizedPreviousScanID := strings.TrimSpace(previousScanID)
	if normalizedPreviousScanID != "" {
		if normalizedPreviousScanID == currentScan.ID {
			return ScanDiff{}, ErrInvalidScanDiffBaseline
		}
		baselineScan, err := s.Store.GetScan(ctx, normalizedPreviousScanID)
		if err != nil {
			return ScanDiff{}, err
		}
		if baselineScan.Provider != currentScan.Provider {
			return ScanDiff{}, ErrInvalidScanDiffBaseline
		}
		if !baselineScan.StartedAt.Before(currentScan.StartedAt) {
			return ScanDiff{}, ErrInvalidScanDiffBaseline
		}
	} else {
		scans, err := s.Store.ListScans(ctx, 500)
		if err != nil {
			return ScanDiff{}, err
		}
		for _, scan := range scans {
			if scan.ID == currentScan.ID || scan.Provider != currentScan.Provider {
				continue
			}
			if scan.StartedAt.Before(currentScan.StartedAt) {
				normalizedPreviousScanID = scan.ID
				break
			}
		}
	}

	diff := ScanDiff{ScanID: scanID, PreviousScanID: normalizedPreviousScanID}
	currentByID := map[string]domain.Finding{}
	for _, finding := range currentFindings {
		currentByID[finding.ID] = finding
	}
	if normalizedPreviousScanID == "" {
		diff.Added = currentFindings
		diff.AddedCount = len(currentFindings)
		diff.applyLimit(limit)
		return diff, nil
	}

	previousFindings, err := s.Store.ListFindingsByScan(ctx, normalizedPreviousScanID, 5000)
	if err != nil {
		return ScanDiff{}, err
	}
	previousByID := map[string]domain.Finding{}
	for _, finding := range previousFindings {
		previousByID[finding.ID] = finding
	}

	for id, finding := range currentByID {
		if _, exists := previousByID[id]; exists {
			diff.Persisting = append(diff.Persisting, finding)
			continue
		}
		diff.Added = append(diff.Added, finding)
	}
	for id, finding := range previousByID {
		if _, exists := currentByID[id]; exists {
			continue
		}
		diff.Resolved = append(diff.Resolved, finding)
	}

	sort.Slice(diff.Added, func(i, j int) bool { return diff.Added[i].CreatedAt.After(diff.Added[j].CreatedAt) })
	sort.Slice(diff.Resolved, func(i, j int) bool { return diff.Resolved[i].CreatedAt.After(diff.Resolved[j].CreatedAt) })
	sort.Slice(diff.Persisting, func(i, j int) bool { return diff.Persisting[i].CreatedAt.After(diff.Persisting[j].CreatedAt) })
	diff.AddedCount = len(diff.Added)
	diff.ResolvedCount = len(diff.Resolved)
	diff.PersistingCount = len(diff.Persisting)
	diff.applyLimit(limit)
	return diff, nil
}

func (s *Service) appendScanEvent(ctx context.Context, scanID string, level string, message string, metadata map[string]any) {
	ctx = s.scopeContext(ctx)
	_ = s.Store.AppendScanEvent(ctx, scanID, level, message, metadata)
}

func (s *Service) appendScanLifecycleEvent(ctx context.Context, scanID string, state string, metadata map[string]any) {
	payload := map[string]any{"state": state}
	for key, value := range metadata {
		payload[key] = value
	}
	s.appendScanEvent(ctx, scanID, db.ScanEventLevelInfo, "scan lifecycle transition", payload)
}

func (d *ScanDiff) applyLimit(limit int) {
	if limit <= 0 {
		return
	}
	if len(d.Added) > limit {
		d.Added = d.Added[:limit]
	}
	if len(d.Resolved) > limit {
		d.Resolved = d.Resolved[:limit]
	}
	if len(d.Persisting) > limit {
		d.Persisting = d.Persisting[:limit]
	}
}

func (s *Service) latestScanID(ctx context.Context) (string, error) {
	ctx = s.scopeContext(ctx)
	scans, err := s.Store.ListScans(ctx, 1)
	if err != nil {
		return "", err
	}
	if len(scans) == 0 {
		return "", db.ErrNotFound
	}
	return scans[0].ID, nil
}

func sanitizeRepoScanLimit(candidate int, fallback int, maxAllowed int) (int, error) {
	if fallback <= 0 {
		fallback = 1
	}
	if maxAllowed <= 0 {
		maxAllowed = fallback
	}
	if candidate < 0 {
		return 0, ErrInvalidRepoScanRequest
	}
	if candidate == 0 {
		candidate = fallback
	}
	if candidate > maxAllowed {
		return 0, ErrInvalidRepoScanRequest
	}
	return candidate, nil
}

func enrichFindings(findings []domain.Finding) []domain.Finding {
	if len(findings) == 0 {
		return findings
	}
	enriched := make([]domain.Finding, 0, len(findings))
	for _, finding := range findings {
		enriched = append(enriched, standards.EnrichFinding(finding))
	}
	return enriched
}

func (s *Service) applyFindingTriageStates(ctx context.Context, findings []domain.Finding) ([]domain.Finding, error) {
	if len(findings) == 0 {
		return findings, nil
	}
	ids := make([]string, 0, len(findings))
	seen := map[string]struct{}{}
	for _, finding := range findings {
		id := strings.TrimSpace(finding.ID)
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	states, err := s.Store.ListFindingTriageStates(ctx, ids)
	if err != nil {
		return nil, err
	}
	byID := map[string]db.FindingTriageState{}
	now := s.Now().UTC()
	for _, state := range states {
		normalized := normalizeFindingTriageState(state, now)
		byID[normalized.FindingID] = normalized
	}
	result := make([]domain.Finding, 0, len(findings))
	for _, finding := range findings {
		triage := domain.DefaultFindingTriage()
		if state, exists := byID[strings.TrimSpace(finding.ID)]; exists {
			updatedAt := state.UpdatedAt.UTC()
			triage = domain.FindingTriage{
				Status:               state.Status,
				Assignee:             state.Assignee,
				SuppressionExpiresAt: state.SuppressionExpiresAt,
				UpdatedAt:            &updatedAt,
				UpdatedBy:            state.UpdatedBy,
			}
		}
		finding.Triage = triage
		result = append(result, finding)
	}
	return result, nil
}

func normalizeFindingTriageState(state db.FindingTriageState, now time.Time) db.FindingTriageState {
	if state.Status == "" {
		state.Status = domain.FindingLifecycleOpen
	}
	if !isValidFindingLifecycleStatus(state.Status) {
		state.Status = domain.FindingLifecycleOpen
	}
	if state.Status == domain.FindingLifecycleSuppressed && state.SuppressionExpiresAt != nil && !state.SuppressionExpiresAt.After(now) {
		state.Status = domain.FindingLifecycleOpen
		state.SuppressionExpiresAt = nil
	}
	if state.Status != domain.FindingLifecycleSuppressed {
		state.SuppressionExpiresAt = nil
	}
	return state
}

func parseFindingLifecycleStatus(raw string) (domain.FindingLifecycleStatus, error) {
	status := domain.FindingLifecycleStatus(strings.ToLower(strings.TrimSpace(raw)))
	if !isValidFindingLifecycleStatus(status) {
		return "", ErrInvalidFindingTriageRequest
	}
	return status, nil
}

func isValidFindingLifecycleStatus(status domain.FindingLifecycleStatus) bool {
	switch status {
	case domain.FindingLifecycleOpen, domain.FindingLifecycleAck, domain.FindingLifecycleSuppressed, domain.FindingLifecycleResolved:
		return true
	default:
		return false
	}
}

func parseSuppressionExpiry(raw string, now time.Time) (*time.Time, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, ErrInvalidFindingTriageRequest
	}
	normalized := parsed.UTC()
	if !normalized.After(now) {
		return nil, ErrInvalidFindingTriageRequest
	}
	return &normalized, nil
}

func timePointersEqual(a *time.Time, b *time.Time) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.UTC().Equal(b.UTC())
}

func normalizeActor(actor string) string {
	normalized := strings.TrimSpace(actor)
	if normalized == "" {
		return "unknown"
	}
	return normalized
}

func deriveFindingTriageAction(current db.FindingTriageState, next db.FindingTriageState, comment string) string {
	if current.Status != next.Status {
		switch next.Status {
		case domain.FindingLifecycleAck:
			return db.FindingTriageActionAcknowledged
		case domain.FindingLifecycleSuppressed:
			return db.FindingTriageActionSuppressed
		case domain.FindingLifecycleResolved:
			return db.FindingTriageActionResolved
		case domain.FindingLifecycleOpen:
			return db.FindingTriageActionReopened
		}
	}
	if current.Assignee != next.Assignee {
		return db.FindingTriageActionAssigned
	}
	if !timePointersEqual(current.SuppressionExpiresAt, next.SuppressionExpiresAt) {
		return db.FindingTriageActionSuppression
	}
	if strings.TrimSpace(comment) != "" {
		return db.FindingTriageActionCommented
	}
	return db.FindingTriageActionCommented
}

func truncateSourceErrors(errors []providers.SourceError, max int) []providers.SourceError {
	if len(errors) == 0 {
		return nil
	}
	if max <= 0 || len(errors) <= max {
		return append([]providers.SourceError(nil), errors...)
	}
	return append([]providers.SourceError(nil), errors[:max]...)
}

func repoTargetAllowed(target string, allowlist []string) bool {
	if len(allowlist) == 0 {
		return false
	}
	normalizedTarget := strings.ToLower(strings.TrimSpace(target))
	if normalizedTarget == "" {
		return false
	}
	for _, item := range allowlist {
		pattern := strings.ToLower(strings.TrimSpace(item))
		if pattern == "" {
			continue
		}
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(normalizedTarget, prefix) {
				return true
			}
			continue
		}
		if normalizedTarget == pattern {
			return true
		}
	}
	return false
}

func inferOwnershipSignal(identity domain.Identity) (domain.OwnershipSignal, bool) {
	ownerHint := strings.TrimSpace(identity.OwnerHint)
	if ownerHint != "" {
		return domain.OwnershipSignal{
			ID:         "ownership:" + identity.ID,
			IdentityID: identity.ID,
			Team:       ownerHint,
			Source:     "owner_hint",
			Confidence: 0.9,
		}, true
	}

	tags := identity.Tags
	team := firstNonEmptyTag(tags, "team", "owner", "team_name")
	repository := firstNonEmptyTag(tags, "repository", "repo", "service_repo")
	if team == "" && repository == "" {
		return domain.OwnershipSignal{}, false
	}
	confidence := 0.65
	source := "tags"
	if team != "" {
		confidence = 0.8
		source = "tags.team"
	}
	if team != "" && repository != "" {
		confidence = 0.85
		source = "tags.team+repository"
	}
	if team == "" && repository != "" {
		confidence = 0.75
		source = "tags.repository"
	}
	return domain.OwnershipSignal{
		ID:         "ownership:" + identity.ID,
		IdentityID: identity.ID,
		Team:       team,
		Repository: repository,
		Source:     source,
		Confidence: confidence,
	}, true
}

func firstNonEmptyTag(tags map[string]string, keys ...string) string {
	for _, key := range keys {
		value := strings.TrimSpace(tags[key])
		if value != "" {
			return value
		}
	}
	return ""
}

func (s *Service) lockKey(key string) string {
	normalizedKey := strings.TrimSpace(key)
	namespace := strings.TrimSpace(s.LockNamespace)
	if namespace == "" {
		return normalizedKey
	}
	if normalizedKey == "" {
		return namespace
	}
	return namespace + ":" + normalizedKey
}

func (s *Service) scopeContext(ctx context.Context) context.Context {
	return db.WithDefaultScope(ctx, s.DefaultScope)
}
