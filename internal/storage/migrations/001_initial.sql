-- Migration 001: initial schema
-- All tables are scoped by installation_id (GitHub App installation).

CREATE TABLE IF NOT EXISTS installations (
    id INTEGER PRIMARY KEY,           -- GitHub App installation ID
    account_login TEXT NOT NULL,       -- org or user login
    account_type TEXT NOT NULL,        -- "Organization" or "User"
    installed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    access_token TEXT,                 -- encrypted (plain for v3.0, encrypt in v3.1)
    token_expires_at DATETIME
);

CREATE TABLE IF NOT EXISTS repositories (
    id INTEGER PRIMARY KEY,           -- GitHub repo ID
    installation_id INTEGER NOT NULL REFERENCES installations(id),
    full_name TEXT NOT NULL,           -- "org/repo"
    default_branch TEXT NOT NULL DEFAULT 'main',
    manifest_sha TEXT,                 -- SHA of last known manifest commit
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_results (
    id TEXT PRIMARY KEY,               -- e.g. "scan-abc123"
    repo_id INTEGER NOT NULL REFERENCES repositories(id),
    pr_number INTEGER NOT NULL,
    commit_sha TEXT NOT NULL,
    base_sha TEXT NOT NULL,
    scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    scan_duration_ms INTEGER,
    capabilities_json TEXT NOT NULL,   -- JSON-encoded []contracts.Capability
    novel_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','verified','expired'))
);

CREATE TABLE IF NOT EXISTS verification_decisions (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scan_results(id),
    capability_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('confirm','revert')),
    justification TEXT,
    decided_by TEXT NOT NULL,          -- GitHub username
    decided_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Useful indexes
CREATE INDEX IF NOT EXISTS idx_repositories_installation ON repositories(installation_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_repo ON scan_results(repo_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_pr ON scan_results(repo_id, pr_number);
CREATE INDEX IF NOT EXISTS idx_verification_scan ON verification_decisions(scan_id);
