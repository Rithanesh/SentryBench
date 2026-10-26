package database

import (
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

// Open opens (and creates if needed) the SQLite database at path and applies
// migrations. Tokens/secrets for identities belong in the OS keychain per
// the security requirements in the implementation plan — this file only
// covers the account/workspace tables needed for login + workspaces.
func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

func migrate(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL UNIQUE,
			display_name TEXT NOT NULL,
			avatar_color TEXT NOT NULL DEFAULT '#6366f1',
			password_hash TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS workspaces (
			id TEXT PRIMARY KEY,
			owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			target_hosts TEXT NOT NULL DEFAULT '[]',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_workspaces_owner ON workspaces(owner_id);`,
		`CREATE TABLE IF NOT EXISTS identities (
			id TEXT PRIMARY KEY,
			workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT '',
			auth_type TEXT NOT NULL,
			token TEXT NOT NULL DEFAULT '',
			headers TEXT NOT NULL DEFAULT '{}',
			cookies TEXT NOT NULL DEFAULT '{}',
			created_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_identities_workspace ON identities(workspace_id);`,
		`CREATE TABLE IF NOT EXISTS saved_requests (
			id TEXT PRIMARY KEY,
			workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			method TEXT NOT NULL,
			url TEXT NOT NULL,
			headers TEXT NOT NULL DEFAULT '{}',
			query TEXT NOT NULL DEFAULT '{}',
			body TEXT NOT NULL DEFAULT '',
			identity_id TEXT,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_saved_requests_workspace ON saved_requests(workspace_id);`,
		`CREATE TABLE IF NOT EXISTS captured_requests (
			id TEXT PRIMARY KEY,
			workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
			method TEXT NOT NULL,
			url TEXT NOT NULL,
			host TEXT NOT NULL,
			path TEXT NOT NULL,
			request_headers TEXT NOT NULL DEFAULT '{}',
			request_body TEXT NOT NULL DEFAULT '',
			response_status INTEGER NOT NULL DEFAULT 0,
			response_headers TEXT NOT NULL DEFAULT '{}',
			response_body TEXT NOT NULL DEFAULT '',
			duration_ms INTEGER NOT NULL DEFAULT 0,
			captured_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_captured_workspace ON captured_requests(workspace_id);`,
		// tab_id is nullable and added via a guarded ALTER (SQLite has no
		// "ADD COLUMN IF NOT EXISTS") so this migration is safe to run
		// again on a database created before the Browser feature existed.
		`ALTER TABLE captured_requests ADD COLUMN tab_id TEXT;`,
		`CREATE INDEX IF NOT EXISTS idx_captured_tab ON captured_requests(tab_id);`,
		`CREATE TABLE IF NOT EXISTS scans (
			id TEXT PRIMARY KEY,
			workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
			status TEXT NOT NULL,
			source TEXT NOT NULL,
			findings_count INTEGER NOT NULL DEFAULT 0,
			started_at TEXT NOT NULL,
			completed_at TEXT,
			error TEXT NOT NULL DEFAULT ''
		);`,
		`CREATE INDEX IF NOT EXISTS idx_scans_workspace ON scans(workspace_id);`,
		`CREATE TABLE IF NOT EXISTS findings (
			id TEXT PRIMARY KEY,
			workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
			scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
			check_id TEXT NOT NULL,
			title TEXT NOT NULL,
			severity TEXT NOT NULL,
			description TEXT NOT NULL,
			evidence TEXT NOT NULL DEFAULT '',
			method TEXT NOT NULL DEFAULT '',
			url TEXT NOT NULL DEFAULT '',
			remediation TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_findings_workspace ON findings(workspace_id);`,
		`CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			// ALTER TABLE ... ADD COLUMN has no "IF NOT EXISTS" in SQLite,
			// so on a database that already has the column (any run after
			// the first time this migration executed), it errors with
			// "duplicate column name" — expected and safe to ignore.
			if strings.HasPrefix(s, "ALTER TABLE") && strings.Contains(err.Error(), "duplicate column name") {
				continue
			}
			return fmt.Errorf("exec migration %q: %w", s, err)
		}
	}
	return nil
}
