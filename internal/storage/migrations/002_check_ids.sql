-- Migration 002: add GitHub check run ID and PR comment ID to scan_results
-- These are needed by the verification engine (Step 3.6) to update the check
-- and comment after a developer confirms/reverts capabilities.

ALTER TABLE scan_results ADD COLUMN check_run_id INTEGER DEFAULT 0;
ALTER TABLE scan_results ADD COLUMN comment_id INTEGER DEFAULT 0;
