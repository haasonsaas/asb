package migrate_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/haasonsaas/asb/internal/migrate"
	pgxmock "github.com/pashagolub/pgxmock/v4"
)

func TestDiscover_SortsMigrationsByVersion(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeMigration(t, dir, "0002_add_index.sql", "SELECT 2;")
	writeMigration(t, dir, "0001_init.sql", "SELECT 1;")

	migrations, err := migrate.Discover(dir)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(migrations) != 2 {
		t.Fatalf("len(migrations) = %d, want 2", len(migrations))
	}
	if migrations[0].Version != "0001" || migrations[1].Version != "0002" {
		t.Fatalf("versions = %q, %q; want 0001, 0002", migrations[0].Version, migrations[1].Version)
	}
}

func TestRunner_UpAppliesPendingMigrations(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeMigration(t, dir, "0001_init.sql", "CREATE TABLE one (id INT);")
	writeMigration(t, dir, "0002_add_index.sql", "CREATE INDEX idx_one_id ON one(id);")

	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer mock.Close()

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS schema_migrations").WillReturnResult(pgxmock.NewResult("CREATE TABLE", 1))
	mock.ExpectQuery("SELECT version FROM schema_migrations").WillReturnRows(pgxmock.NewRows([]string{"version"}).AddRow("0001"))
	mock.ExpectExec("CREATE INDEX idx_one_id ON one").WillReturnResult(pgxmock.NewResult("CREATE INDEX", 1))
	mock.ExpectExec("INSERT INTO schema_migrations").WithArgs("0002", "add_index").WillReturnResult(pgxmock.NewResult("INSERT", 1))

	runner := migrate.NewRunner(mock)
	applied, err := runner.Up(context.Background(), dir)
	if err != nil {
		t.Fatalf("Up() error = %v", err)
	}
	if len(applied) != 1 || applied[0].Version != "0002" {
		t.Fatalf("applied = %#v, want only 0002", applied)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("ExpectationsWereMet() error = %v", err)
	}
}

func writeMigration(t *testing.T, dir string, name string, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}
