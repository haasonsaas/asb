package migrate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type queryable interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

type Runner struct {
	db queryable
}

type Migration struct {
	Version string
	Name    string
	Path    string
	SQL     string
}

type Status struct {
	Migration Migration
	Applied   bool
}

func NewRunner(db queryable) *Runner {
	return &Runner{db: db}
}

func Discover(dir string) ([]Migration, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	migrations := make([]Migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		base := strings.TrimSuffix(entry.Name(), ".sql")
		parts := strings.SplitN(base, "_", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid migration filename %q", entry.Name())
		}
		path := filepath.Join(dir, entry.Name())
		contents, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		migrations = append(migrations, Migration{
			Version: parts[0],
			Name:    parts[1],
			Path:    path,
			SQL:     string(contents),
		})
	}

	sort.Slice(migrations, func(i int, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})
	return migrations, nil
}

func (r *Runner) Status(ctx context.Context, dir string) ([]Status, error) {
	if err := r.ensureSchemaMigrations(ctx); err != nil {
		return nil, err
	}
	migrations, err := Discover(dir)
	if err != nil {
		return nil, err
	}
	applied, err := r.appliedVersions(ctx)
	if err != nil {
		return nil, err
	}

	statuses := make([]Status, 0, len(migrations))
	for _, migration := range migrations {
		_, ok := applied[migration.Version]
		statuses = append(statuses, Status{
			Migration: migration,
			Applied:   ok,
		})
	}
	return statuses, nil
}

func (r *Runner) Up(ctx context.Context, dir string) ([]Migration, error) {
	statuses, err := r.Status(ctx, dir)
	if err != nil {
		return nil, err
	}

	applied := make([]Migration, 0)
	for _, status := range statuses {
		if status.Applied {
			continue
		}
		if _, err := r.db.Exec(ctx, status.Migration.SQL); err != nil {
			return nil, fmt.Errorf("apply migration %s: %w", status.Migration.Version, err)
		}
		if _, err := r.db.Exec(ctx, `
			INSERT INTO schema_migrations (version, name, applied_at)
			VALUES ($1, $2, NOW())
		`, status.Migration.Version, status.Migration.Name); err != nil {
			return nil, fmt.Errorf("record migration %s: %w", status.Migration.Version, err)
		}
		applied = append(applied, status.Migration)
	}
	return applied, nil
}

func (r *Runner) ensureSchemaMigrations(ctx context.Context) error {
	_, err := r.db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	return err
}

func (r *Runner) appliedVersions(ctx context.Context) (map[string]struct{}, error) {
	rows, err := r.db.Query(ctx, `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	versions := make(map[string]struct{})
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		versions[version] = struct{}{}
	}
	return versions, rows.Err()
}
