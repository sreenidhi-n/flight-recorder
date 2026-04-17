-- Migration 005: tamper-evident audit event log.
--
-- Each row records one security-relevant action and is linked to the previous
-- row for the same tenant via a SHA-256 hash chain.  Modifying or deleting
-- any row breaks the chain and is detected by GET /audit/:repo/verify.
--
-- Compliance:
--   SOC 2:       CC7.2 (monitoring), CC7.3 (evaluating security events)
--   ISO 27001:   A.8.15 (logging), A.8.16 (monitoring activities)
--   NIST 800-53: AU-2, AU-3, AU-9, AU-9(3), AU-10, AU-10(3), AU-12

CREATE TABLE IF NOT EXISTS audit_events (
    id           TEXT     PRIMARY KEY,         -- uuid v4
    ts           DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    tenant_id    INTEGER  NOT NULL,            -- installation_id (GitHub App tenant)
    actor_gh_id  INTEGER  NOT NULL DEFAULT 0, -- GitHub user ID of the actor
    actor_login  TEXT     NOT NULL DEFAULT '', -- GitHub login of the actor
    repo         TEXT     NOT NULL DEFAULT '', -- "owner/repo" or "" for install-level
    action       TEXT     NOT NULL,           -- see audit.Action constants
    target_id    TEXT     NOT NULL DEFAULT '', -- scan_id, cap_id, etc.
    before_json  TEXT     NOT NULL DEFAULT '', -- state before (no source code)
    after_json   TEXT     NOT NULL DEFAULT '', -- state after  (no source code)
    ip           TEXT     NOT NULL DEFAULT '',
    user_agent   TEXT     NOT NULL DEFAULT '',
    prev_hash    TEXT     NOT NULL DEFAULT '', -- hash of prior row for this tenant ('' for first)
    hash         TEXT     NOT NULL DEFAULT ''  -- SHA-256 of canonical(this row minus hash)
);

CREATE INDEX IF NOT EXISTS idx_audit_events_tenant
    ON audit_events(tenant_id, ts);
CREATE INDEX IF NOT EXISTS idx_audit_events_repo
    ON audit_events(tenant_id, repo, ts);
