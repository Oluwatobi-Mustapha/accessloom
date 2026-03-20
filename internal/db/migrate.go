package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ApplyMigrations runs all *.up.sql files in lexical order.
func (p *PostgresStore) ApplyMigrations(ctx context.Context, dir string) error {
	if p == nil || p.db == nil {
		return fmt.Errorf("postgres store is not initialized")
	}
	return ApplyMigrations(ctx, p.db, dir)
}

// ApplyDownMigrations runs all *.down.sql files in reverse lexical order.
func (p *PostgresStore) ApplyDownMigrations(ctx context.Context, dir string) error {
	if p == nil || p.db == nil {
		return fmt.Errorf("postgres store is not initialized")
	}
	return ApplyDownMigrations(ctx, p.db, dir)
}

// ApplyMigrations applies migration scripts from directory against db.
func ApplyMigrations(ctx context.Context, db *sql.DB, dir string) error {
	if db == nil {
		return fmt.Errorf("database is not initialized")
	}
	files, err := migrationFiles(dir)
	if err != nil {
		return err
	}
	return applyMigrationFiles(ctx, db, files)
}

// ApplyDownMigrations applies down migration scripts in rollback order.
func ApplyDownMigrations(ctx context.Context, db *sql.DB, dir string) error {
	if db == nil {
		return fmt.Errorf("database is not initialized")
	}
	files, err := downMigrationFiles(dir)
	if err != nil {
		return err
	}
	return applyMigrationFiles(ctx, db, files)
}

func applyMigrationFiles(ctx context.Context, db *sql.DB, files []string) error {
	for _, file := range files {
		query, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", file, err)
		}
		if strings.TrimSpace(string(query)) == "" {
			continue
		}
		if _, err := db.ExecContext(ctx, string(query)); err != nil {
			return fmt.Errorf("apply migration %s: %w", filepath.Base(file), err)
		}
	}
	return nil
}

func migrationFiles(dir string) ([]string, error) {
	files, err := migrationFilesBySuffix(dir, ".up.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func downMigrationFiles(dir string) ([]string, error) {
	files, err := migrationFilesBySuffix(dir, ".down.sql")
	if err != nil {
		return nil, err
	}
	sort.Sort(sort.Reverse(sort.StringSlice(files)))
	return files, nil
}

func migrationFilesBySuffix(dir string, suffix string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations dir %s: %w", dir, err)
	}

	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, suffix) {
			files = append(files, filepath.Join(dir, name))
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no %s migrations found in %s", suffix, dir)
	}
	return files, nil
}
