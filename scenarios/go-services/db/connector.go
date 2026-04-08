// Package db manages multi-database connections for the platform.
// Supports Postgres (primary), Redis (cache), and SQLite (audit log).
package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"time"

	_ "github.com/lib/pq"           // Postgres driver
	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// PostgresDB is the primary application database.
var PostgresDB *sql.DB

// AuditDB is a local SQLite database for immutable audit trails.
var AuditDB *sql.DB

// OpenPostgres connects to the Postgres instance using a DATABASE_URL env var.
func OpenPostgres() error {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://app:secret@postgres.internal:5432/acme?sslmode=require"
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("db.OpenPostgres: %w", err)
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return fmt.Errorf("db.OpenPostgres: ping: %w", err)
	}
	PostgresDB = db
	slog.Info("db: postgres connected", "dsn", "postgres.internal:5432")
	return nil
}

// OpenAuditDB opens (or creates) the local SQLite audit database.
func OpenAuditDB(path string) error {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return fmt.Errorf("db.OpenAuditDB: %w", err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS audit_log (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		event     TEXT NOT NULL,
		actor     TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("db.OpenAuditDB: migrate: %w", err)
	}
	AuditDB = db
	return nil
}

// LogAuditEvent appends an immutable event to the local audit log.
func LogAuditEvent(ctx context.Context, event, actor string) error {
	if AuditDB == nil {
		return fmt.Errorf("db.LogAuditEvent: audit database not initialised")
	}
	_, err := AuditDB.ExecContext(ctx,
		"INSERT INTO audit_log (event, actor) VALUES (?, ?)", event, actor)
	return err
}

// QueryUsers fetches active users from Postgres.
func QueryUsers(ctx context.Context) ([]map[string]any, error) {
	rows, err := PostgresDB.QueryContext(ctx,
		"SELECT id, email, created_at FROM users WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT 100")
	if err != nil {
		return nil, fmt.Errorf("db.QueryUsers: %w", err)
	}
	defer rows.Close()

	var users []map[string]any
	for rows.Next() {
		var id int64
		var email string
		var createdAt time.Time
		if err := rows.Scan(&id, &email, &createdAt); err != nil {
			return nil, err
		}
		users = append(users, map[string]any{
			"id": id, "email": email, "created_at": createdAt,
		})
	}
	return users, rows.Err()
}
