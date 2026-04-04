package runtime

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/api"
	"github.com/Oluwatobi-Mustapha/identrail/internal/app"
	"github.com/Oluwatobi-Mustapha/identrail/internal/config"
	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	awsprovider "github.com/Oluwatobi-Mustapha/identrail/internal/providers/aws"
	k8sprovider "github.com/Oluwatobi-Mustapha/identrail/internal/providers/kubernetes"
	"github.com/Oluwatobi-Mustapha/identrail/internal/scheduler"
)

// BuildScanService constructs store + scanner + API service from runtime config.
func BuildScanService(cfg config.Config) (*api.Service, func() error, error) {
	var store db.Store
	var pgStore *db.PostgresStore
	if cfg.DatabaseURL == "" {
		store = db.NewMemoryStore()
	} else {
		var pgErr error
		pgStore, pgErr = db.NewPostgresStore(cfg.DatabaseURL)
		if pgErr != nil {
			return nil, nil, fmt.Errorf("initialize postgres store: %w", pgErr)
		}
		if cfg.RunMigrations {
			migrateCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if migrateErr := pgStore.ApplyMigrations(migrateCtx, cfg.MigrationsDir); migrateErr != nil {
				_ = pgStore.Close()
				return nil, nil, fmt.Errorf("apply migrations: %w", migrateErr)
			}
		}
		store = pgStore
	}

	var scanner app.Scanner
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "aws":
		switch strings.ToLower(strings.TrimSpace(cfg.AWSSource)) {
		case "", "fixture":
			scanner = app.Scanner{
				Collector:            awsprovider.NewFixtureCollector(cfg.AWSFixturePath),
				Normalizer:           awsprovider.NewRoleNormalizer(),
				PermissionResolver:   awsprovider.NewPolicyPermissionResolver(),
				RelationshipResolver: awsprovider.NewRelationshipBuilder(),
				RiskRuleSet:          awsprovider.NewRuleSet(),
			}
		case "sdk":
			iamAPI, iamErr := awsprovider.NewSDKIAMAPI(cfg.AWSRegion, cfg.AWSProfile)
			if iamErr != nil {
				_ = store.Close()
				return nil, nil, fmt.Errorf("initialize aws sdk collector: %w", iamErr)
			}
			scanner = app.Scanner{
				Collector:            awsprovider.NewCollector(iamAPI),
				Normalizer:           awsprovider.NewRoleNormalizer(),
				PermissionResolver:   awsprovider.NewPolicyPermissionResolver(),
				RelationshipResolver: awsprovider.NewRelationshipBuilder(),
				RiskRuleSet:          awsprovider.NewRuleSet(),
			}
		default:
			_ = store.Close()
			return nil, nil, fmt.Errorf("unsupported aws source %q", cfg.AWSSource)
		}
	case "kubernetes":
		var collector app.Scanner
		switch strings.ToLower(strings.TrimSpace(cfg.KubernetesSource)) {
		case "", "fixture":
			collector = app.Scanner{
				Collector:            k8sprovider.NewFixtureCollector(cfg.KubernetesFixturePath),
				Normalizer:           k8sprovider.NewNormalizer(),
				PermissionResolver:   k8sprovider.NewPermissionResolver(),
				RelationshipResolver: k8sprovider.NewRelationshipResolver(),
				RiskRuleSet:          k8sprovider.NewRuleSet(),
			}
		case "kubectl":
			collector = app.Scanner{
				Collector:            k8sprovider.NewKubectlCollector(cfg.KubectlPath, cfg.KubeContext, nil),
				Normalizer:           k8sprovider.NewNormalizer(),
				PermissionResolver:   k8sprovider.NewPermissionResolver(),
				RelationshipResolver: k8sprovider.NewRelationshipResolver(),
				RiskRuleSet:          k8sprovider.NewRuleSet(),
			}
		default:
			_ = store.Close()
			return nil, nil, fmt.Errorf("unsupported kubernetes source %q", cfg.KubernetesSource)
		}
		scanner = collector
	default:
		_ = store.Close()
		return nil, nil, fmt.Errorf("unsupported provider %q", cfg.Provider)
	}

	svc := api.NewService(store, scanner, cfg.Provider)
	svc.DefaultScope = db.Scope{
		TenantID:    cfg.DefaultTenantID,
		WorkspaceID: cfg.DefaultWorkspaceID,
	}.Normalize()
	svc.LockNamespace = strings.TrimSpace(cfg.LockNamespace)
	lockBackend := strings.ToLower(strings.TrimSpace(cfg.LockBackend))
	switch lockBackend {
	case "", "auto":
		if pgStore != nil {
			svc.Locker = scheduler.NewPostgresAdvisoryLocker(pgStore.DB())
		}
	case "postgres":
		if pgStore != nil {
			svc.Locker = scheduler.NewPostgresAdvisoryLocker(pgStore.DB())
		}
	case "inmemory":
		svc.Locker = scheduler.NewInMemoryLocker()
	default:
		// Validation should catch this; keep in-memory as safe fallback.
		svc.Locker = scheduler.NewInMemoryLocker()
	}
	svc.RepoScanEnabled = cfg.RepoScanEnabled
	if cfg.RepoScanHistoryLimit > 0 {
		svc.RepoScanDefaultHistoryLimit = cfg.RepoScanHistoryLimit
	}
	if cfg.RepoScanMaxFindings > 0 {
		svc.RepoScanDefaultMaxFindings = cfg.RepoScanMaxFindings
	}
	if cfg.RepoScanHistoryLimitMax > 0 {
		svc.RepoScanMaxHistoryLimit = cfg.RepoScanHistoryLimitMax
	}
	if cfg.RepoScanMaxFindingsMax > 0 {
		svc.RepoScanMaxFindingsLimit = cfg.RepoScanMaxFindingsMax
	}
	svc.RepoScanAllowedTargets = append([]string(nil), cfg.RepoScanAllowlist...)
	if cfg.ScanQueueMaxPending > 0 {
		svc.ScanQueueMaxPending = cfg.ScanQueueMaxPending
	}
	if cfg.RepoQueueMaxPending > 0 {
		svc.RepoQueueMaxPending = cfg.RepoQueueMaxPending
	}
	if cfg.AlertWebhookURL != "" {
		alerter, alertErr := api.NewWebhookAlerter(
			cfg.AlertWebhookURL,
			cfg.AlertTimeout,
			cfg.AlertMinSeverity,
			cfg.AlertHMACSecret,
			cfg.AlertMaxFindings,
			cfg.AlertMaxRetries,
			cfg.AlertRetryBackoff,
		)
		if alertErr != nil {
			_ = store.Close()
			return nil, nil, fmt.Errorf("initialize alert webhook: %w", alertErr)
		}
		svc.Alerter = alerter
	}
	return svc, store.Close, nil
}

// NewStore returns memory store by default, Postgres when database URL is provided.
func NewStore(databaseURL string) (db.Store, error) {
	if databaseURL == "" {
		return db.NewMemoryStore(), nil
	}
	store, err := db.NewPostgresStore(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("initialize postgres store: %w", err)
	}
	return store, nil
}
