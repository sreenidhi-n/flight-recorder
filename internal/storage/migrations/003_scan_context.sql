-- Migration 003: add PR branch and installation ID to scan_results
-- The verifier (Step 3.6) needs these to commit the manifest and refresh tokens
-- without re-querying GitHub.

ALTER TABLE scan_results ADD COLUMN head_branch TEXT NOT NULL DEFAULT '';
ALTER TABLE scan_results ADD COLUMN installation_id INTEGER NOT NULL DEFAULT 0;
