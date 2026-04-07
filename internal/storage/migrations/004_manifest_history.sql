-- Migration 004: manifest history for the audit trail.
-- Each row records one manifest commit: content snapshot, who triggered it, when.

CREATE TABLE IF NOT EXISTS manifest_history (
    id           TEXT PRIMARY KEY,
    repo_id      INTEGER NOT NULL REFERENCES repositories(id),
    commit_sha   TEXT NOT NULL,           -- PR head SHA at time of commit
    content_yaml TEXT NOT NULL,           -- full tass.manifest.yaml content
    committed_by TEXT NOT NULL,           -- GitHub login of the deciding developer
    committed_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_manifest_history_repo
    ON manifest_history(repo_id, committed_at);
