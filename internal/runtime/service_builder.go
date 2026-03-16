package runtime

import (
	"context"
	"fmt"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/api"
	"github.com/Oluwatobi-Mustapha/identrail/internal/app"
	"github.com/Oluwatobi-Mustapha/identrail/internal/config"
	"github.com/Oluwatobi-Mustapha/identrail/internal/db"
	awsprovider "github.com/Oluwatobi-Mustapha/identrail/internal/providers/aws"
)

// BuildScanService constructs store + scanner + API service from runtime config.
func BuildScanService(cfg config.Config) (*api.Service, func() error, error) {
	var store db.Store
	if cfg.DatabaseURL == "" {
		store = db.NewMemoryStore()
	} else {
		pgStore, pgErr := db.NewPostgresStore(cfg.DatabaseURL)
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

	scanner := app.Scanner{
		Collector:            awsprovider.NewFixtureCollector(cfg.AWSFixturePath),
		Normalizer:           awsprovider.NewRoleNormalizer(),
		PermissionResolver:   awsprovider.NewPolicyPermissionResolver(),
		RelationshipResolver: awsprovider.NewRelationshipBuilder(),
		RiskRuleSet:          awsprovider.NewRuleSet(),
	}

	svc := api.NewService(store, scanner, cfg.Provider)
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
