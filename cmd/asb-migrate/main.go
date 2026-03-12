package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/haasonsaas/asb/internal/migrate"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	var (
		dir    string
		action string
	)
	flag.StringVar(&dir, "dir", "db/migrations", "directory containing SQL migration files")
	flag.StringVar(&action, "action", "up", "migration action: up or status")
	flag.Parse()

	dsn := os.Getenv("ASB_POSTGRES_DSN")
	if dsn == "" {
		logger.Error("missing postgres dsn", "required_env", "ASB_POSTGRES_DSN")
		os.Exit(1)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		logger.Error("connect postgres", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	runner := migrate.NewRunner(pool)

	switch action {
	case "up":
		applied, err := runner.Up(ctx, dir)
		if err != nil {
			logger.Error("apply migrations", "error", err)
			os.Exit(1)
		}
		if len(applied) == 0 {
			logger.Info("no pending migrations")
			return
		}
		for _, migration := range applied {
			logger.Info("applied migration", "version", migration.Version, "name", migration.Name)
		}
	case "status":
		statuses, err := runner.Status(ctx, dir)
		if err != nil {
			logger.Error("migration status", "error", err)
			os.Exit(1)
		}
		for _, status := range statuses {
			state := "pending"
			if status.Applied {
				state = "applied"
			}
			fmt.Printf("%s\t%s\t%s\n", status.Migration.Version, status.Migration.Name, state)
		}
	default:
		logger.Error("unknown action", "action", action)
		os.Exit(1)
	}
}
