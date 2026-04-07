// Package storage provides the SQLite-backed multi-tenant storage layer.
// Every query is scoped by installation_id or repo_id — never cross-tenant.
package storage

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/tass-security/tass/pkg/contracts"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store is the primary interface for all persistence operations.
// All methods are scoped by installation or repo to enforce tenant isolation.
type Store interface {
	// Installation management
	UpsertInstallation(ctx context.Context, inst Installation) error
	GetInstallation(ctx context.Context, id int64) (*Installation, error)

	// Repository management
	UpsertRepository(ctx context.Context, repo Repository) error
	GetRepository(ctx context.Context, id int64) (*Repository, error)
	GetRepositoryByFullName(ctx context.Context, installationID int64, fullName string) (*Repository, error)
	UpdateManifestSHA(ctx context.Context, repoID int64, sha string) error

	// Scan results
	SaveScan(ctx context.Context, scan ScanResult) error
	GetScan(ctx context.Context, id string) (*ScanResult, error)
	GetScansByRepo(ctx context.Context, repoID int64, limit int) ([]ScanResult, error)
	UpdateScanStatus(ctx context.Context, id string, status ScanStatus) error

	// Verification decisions
	SaveDecision(ctx context.Context, d VerificationDecision) error
	GetDecisionsByScan(ctx context.Context, scanID string) ([]VerificationDecision, error)

	// Analytics
	GetStats(ctx context.Context, repoID int64) (*RepoStats, error)
	GetStatsByInstallation(ctx context.Context, installationID int64) (*InstallationStats, error)
	GetRecentScans(ctx context.Context, installationID int64, limit int) ([]RecentScan, error)

	Close() error
}

// --- Domain types ---

type Installation struct {
	ID             int64
	AccountLogin   string
	AccountType    string // "Organization" or "User"
	InstalledAt    time.Time
	AccessToken    string
	TokenExpiresAt time.Time
}

type Repository struct {
	ID             int64
	InstallationID int64
	FullName       string
	DefaultBranch  string
	ManifestSHA    string
	CreatedAt      time.Time
}

type ScanStatus string

const (
	StatusPending  ScanStatus = "pending"
	StatusVerified ScanStatus = "verified"
	StatusExpired  ScanStatus = "expired"
)

type ScanResult struct {
	ID             string
	RepoID         int64
	InstallationID int64
	PRNumber       int
	HeadBranch     string // PR branch name — needed to commit manifest
	CommitSHA      string
	BaseSHA        string
	ScannedAt      time.Time
	ScanDurationMS int64
	Capabilities   []contracts.Capability
	NovelCount     int
	Status         ScanStatus
	CheckRunID     int64  // GitHub Check Run ID for updating check status
	CommentID      int64  // GitHub PR Comment ID for updating the comment
	FullName       string // e.g. "owner/repo" — joined from repositories
}

type VerificationDecision struct {
	ID            string
	ScanID        string
	CapabilityID  string
	Decision      contracts.VerificationDecision
	Justification string
	DecidedBy     string
	DecidedAt     time.Time
}

// DeveloperStats tracks decisions made by a specific developer.
type DeveloperStats struct {
	ConfirmCount int
	RevertCount  int
}

// CategoryStats tracks detected + decided capability counts per category.
type CategoryStats struct {
	TotalDetected int
	ConfirmCount  int
	RevertCount   int
}

type RepoStats struct {
	RepoID        int64
	TotalScans    int
	TotalCaps     int
	ConfirmCount  int
	RevertCount   int
	AvgDurationMS float64
	ByDeveloper   map[string]DeveloperStats
	ByCategory    map[string]CategoryStats
}

// RecentScan is a lightweight scan summary used for the dashboard recent-scans table.
// It is populated via a JOIN with repositories so callers get the full repo name without
// a second round-trip.
type RecentScan struct {
	ID         string
	RepoID     int64
	FullName   string // joined from repositories
	PRNumber   int
	HeadBranch string
	NovelCount int
	Status     ScanStatus
	ScannedAt  time.Time
}

// InstallationStats aggregates analytics across all repos under one GitHub App installation.
type InstallationStats struct {
	InstallationID int64
	TotalRepos     int
	TotalScans     int
	TotalCaps      int
	ConfirmCount   int
	RevertCount    int
	ByDeveloper    map[string]DeveloperStats
}

// --- SQLiteStore ---

type SQLiteStore struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at the given path and runs migrations.
func Open(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("storage: open db: %w", err)
	}

	// WAL mode for concurrent reads while writing
	if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		return nil, fmt.Errorf("storage: set WAL mode: %w", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON;"); err != nil {
		return nil, fmt.Errorf("storage: enable foreign keys: %w", err)
	}

	s := &SQLiteStore{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("storage: migrate: %w", err)
	}
	return s, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// migrate runs all SQL files in migrations/ in lexicographic order.
func (s *SQLiteStore) migrate() error {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		data, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		if _, err := s.db.Exec(string(data)); err != nil {
			return fmt.Errorf("run migration %s: %w", name, err)
		}
	}
	return nil
}

// --- Installation ---

func (s *SQLiteStore) UpsertInstallation(ctx context.Context, inst Installation) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO installations (id, account_login, account_type, installed_at, access_token, token_expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			account_login    = excluded.account_login,
			account_type     = excluded.account_type,
			access_token     = excluded.access_token,
			token_expires_at = excluded.token_expires_at
	`, inst.ID, inst.AccountLogin, inst.AccountType,
		inst.InstalledAt.UTC(), inst.AccessToken, inst.TokenExpiresAt.UTC())
	if err != nil {
		return fmt.Errorf("storage: upsert installation %d: %w", inst.ID, err)
	}
	return nil
}

func (s *SQLiteStore) GetInstallation(ctx context.Context, id int64) (*Installation, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, account_login, account_type, installed_at, access_token, token_expires_at
		FROM installations WHERE id = ?
	`, id)
	var inst Installation
	var installedAt, tokenExp string
	err := row.Scan(&inst.ID, &inst.AccountLogin, &inst.AccountType,
		&installedAt, &inst.AccessToken, &tokenExp)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("storage: get installation %d: %w", id, err)
	}
	inst.InstalledAt, _ = time.Parse(time.RFC3339, installedAt)
	inst.TokenExpiresAt, _ = time.Parse(time.RFC3339, tokenExp)
	return &inst, nil
}

// --- Repository ---

func (s *SQLiteStore) UpsertRepository(ctx context.Context, repo Repository) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO repositories (id, installation_id, full_name, default_branch, manifest_sha, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			full_name      = excluded.full_name,
			default_branch = excluded.default_branch,
			manifest_sha   = excluded.manifest_sha
	`, repo.ID, repo.InstallationID, repo.FullName, repo.DefaultBranch,
		repo.ManifestSHA, repo.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("storage: upsert repo %d: %w", repo.ID, err)
	}
	return nil
}

func (s *SQLiteStore) GetRepository(ctx context.Context, id int64) (*Repository, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, installation_id, full_name, default_branch, COALESCE(manifest_sha,''), created_at
		FROM repositories WHERE id = ?
	`, id)
	return scanRepository(row)
}

func (s *SQLiteStore) GetRepositoryByFullName(ctx context.Context, installationID int64, fullName string) (*Repository, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, installation_id, full_name, default_branch, COALESCE(manifest_sha,''), created_at
		FROM repositories WHERE installation_id = ? AND full_name = ?
	`, installationID, fullName)
	return scanRepository(row)
}

func (s *SQLiteStore) UpdateManifestSHA(ctx context.Context, repoID int64, sha string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE repositories SET manifest_sha = ? WHERE id = ?`, sha, repoID)
	if err != nil {
		return fmt.Errorf("storage: update manifest sha for repo %d: %w", repoID, err)
	}
	return nil
}

func scanRepository(row *sql.Row) (*Repository, error) {
	var r Repository
	var createdAt string
	err := row.Scan(&r.ID, &r.InstallationID, &r.FullName, &r.DefaultBranch, &r.ManifestSHA, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("storage: scan repository: %w", err)
	}
	r.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &r, nil
}

// --- Scan results ---

func (s *SQLiteStore) SaveScan(ctx context.Context, scan ScanResult) error {
	capsJSON, err := json.Marshal(scan.Capabilities)
	if err != nil {
		return fmt.Errorf("storage: marshal capabilities: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO scan_results
			(id, repo_id, installation_id, pr_number, head_branch,
			 commit_sha, base_sha, scanned_at,
			 scan_duration_ms, capabilities_json, novel_count, status,
			 check_run_id, comment_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, scan.ID, scan.RepoID, scan.InstallationID, scan.PRNumber, scan.HeadBranch,
		scan.CommitSHA, scan.BaseSHA,
		scan.ScannedAt.UTC(), scan.ScanDurationMS, string(capsJSON),
		scan.NovelCount, scan.Status, scan.CheckRunID, scan.CommentID)
	if err != nil {
		return fmt.Errorf("storage: save scan %s: %w", scan.ID, err)
	}
	return nil
}

func (s *SQLiteStore) GetScan(ctx context.Context, id string) (*ScanResult, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT sr.id, sr.repo_id, COALESCE(sr.installation_id,0), sr.pr_number, COALESCE(sr.head_branch,''),
		       sr.commit_sha, sr.base_sha, sr.scanned_at,
		       sr.scan_duration_ms, sr.capabilities_json, sr.novel_count, sr.status,
		       COALESCE(sr.check_run_id,0), COALESCE(sr.comment_id,0),
		       COALESCE(r.full_name,'')
		FROM scan_results sr
		LEFT JOIN repositories r ON r.id = sr.repo_id
		WHERE sr.id = ?
	`, id)
	return scanScanResult(row)
}

func (s *SQLiteStore) GetScansByRepo(ctx context.Context, repoID int64, limit int) ([]ScanResult, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT sr.id, sr.repo_id, COALESCE(sr.installation_id,0), sr.pr_number, COALESCE(sr.head_branch,''),
		       sr.commit_sha, sr.base_sha, sr.scanned_at,
		       sr.scan_duration_ms, sr.capabilities_json, sr.novel_count, sr.status,
		       COALESCE(sr.check_run_id,0), COALESCE(sr.comment_id,0),
		       COALESCE(r.full_name,'')
		FROM scan_results sr
		LEFT JOIN repositories r ON r.id = sr.repo_id
		WHERE sr.repo_id = ?
		ORDER BY sr.scanned_at DESC LIMIT ?
	`, repoID, limit)
	if err != nil {
		return nil, fmt.Errorf("storage: get scans by repo %d: %w", repoID, err)
	}
	defer rows.Close()

	var results []ScanResult
	for rows.Next() {
		sr, err := scanScanResult(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, *sr)
	}
	return results, rows.Err()
}

func (s *SQLiteStore) UpdateScanStatus(ctx context.Context, id string, status ScanStatus) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE scan_results SET status = ? WHERE id = ?`, string(status), id)
	if err != nil {
		return fmt.Errorf("storage: update scan status %s: %w", id, err)
	}
	return nil
}

// scanScanResult works for both *sql.Row and *sql.Rows via the common interface.
type scanner interface {
	Scan(dest ...any) error
}

func scanScanResult(row scanner) (*ScanResult, error) {
	var sr ScanResult
	var scannedAt, capsJSON, status string
	err := row.Scan(&sr.ID, &sr.RepoID, &sr.InstallationID, &sr.PRNumber, &sr.HeadBranch,
		&sr.CommitSHA, &sr.BaseSHA,
		&scannedAt, &sr.ScanDurationMS, &capsJSON, &sr.NovelCount, &status,
		&sr.CheckRunID, &sr.CommentID, &sr.FullName)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("storage: scan scan_result row: %w", err)
	}
	sr.ScannedAt, _ = time.Parse(time.RFC3339, scannedAt)
	sr.Status = ScanStatus(status)
	if err := json.Unmarshal([]byte(capsJSON), &sr.Capabilities); err != nil {
		return nil, fmt.Errorf("storage: unmarshal capabilities: %w", err)
	}
	return &sr, nil
}

// --- Verification decisions ---

func (s *SQLiteStore) SaveDecision(ctx context.Context, d VerificationDecision) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO verification_decisions
			(id, scan_id, capability_id, decision, justification, decided_by, decided_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, d.ID, d.ScanID, d.CapabilityID, string(d.Decision),
		d.Justification, d.DecidedBy, d.DecidedAt.UTC())
	if err != nil {
		return fmt.Errorf("storage: save decision %s: %w", d.ID, err)
	}
	return nil
}

func (s *SQLiteStore) GetDecisionsByScan(ctx context.Context, scanID string) ([]VerificationDecision, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, scan_id, capability_id, decision, COALESCE(justification,''), decided_by, decided_at
		FROM verification_decisions WHERE scan_id = ?
		ORDER BY decided_at ASC
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("storage: get decisions for scan %s: %w", scanID, err)
	}
	defer rows.Close()

	var decisions []VerificationDecision
	for rows.Next() {
		var d VerificationDecision
		var decidedAt, decision string
		if err := rows.Scan(&d.ID, &d.ScanID, &d.CapabilityID, &decision,
			&d.Justification, &d.DecidedBy, &decidedAt); err != nil {
			return nil, fmt.Errorf("storage: scan decision row: %w", err)
		}
		d.Decision = contracts.VerificationDecision(decision)
		d.DecidedAt, _ = time.Parse(time.RFC3339, decidedAt)
		decisions = append(decisions, d)
	}
	return decisions, rows.Err()
}

// --- Analytics ---

func (s *SQLiteStore) GetStats(ctx context.Context, repoID int64) (*RepoStats, error) {
	stats := &RepoStats{
		RepoID:      repoID,
		ByDeveloper: make(map[string]DeveloperStats),
		ByCategory:  make(map[string]CategoryStats),
	}

	row := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(SUM(novel_count),0), COALESCE(AVG(scan_duration_ms),0)
		FROM scan_results WHERE repo_id = ?
	`, repoID)
	if err := row.Scan(&stats.TotalScans, &stats.TotalCaps, &stats.AvgDurationMS); err != nil {
		return nil, fmt.Errorf("storage: get scan stats for repo %d: %w", repoID, err)
	}

	// Per-developer breakdown
	devRows, err := s.db.QueryContext(ctx, `
		SELECT vd.decided_by,
			SUM(CASE WHEN vd.decision = 'confirm' THEN 1 ELSE 0 END),
			SUM(CASE WHEN vd.decision = 'revert'  THEN 1 ELSE 0 END)
		FROM verification_decisions vd
		JOIN scan_results sr ON sr.id = vd.scan_id
		WHERE sr.repo_id = ?
		GROUP BY vd.decided_by
	`, repoID)
	if err != nil {
		return nil, fmt.Errorf("storage: get developer stats for repo %d: %w", repoID, err)
	}
	defer devRows.Close()
	for devRows.Next() {
		var dev string
		var ds DeveloperStats
		if err := devRows.Scan(&dev, &ds.ConfirmCount, &ds.RevertCount); err != nil {
			return nil, fmt.Errorf("storage: scan developer stats row: %w", err)
		}
		stats.ByDeveloper[dev] = ds
		stats.ConfirmCount += ds.ConfirmCount
		stats.RevertCount += ds.RevertCount
	}
	if err := devRows.Err(); err != nil {
		return nil, fmt.Errorf("storage: developer stats rows: %w", err)
	}

	// Build capID→category from scan capabilities, and count detections per category
	capIDToCategory, err := s.buildCapCategoryMap(ctx, repoID)
	if err != nil {
		return nil, err
	}
	for _, cat := range capIDToCategory {
		cs := stats.ByCategory[string(cat)]
		cs.TotalDetected++
		stats.ByCategory[string(cat)] = cs
	}

	// Per-category decision counts
	dcRows, err := s.db.QueryContext(ctx, `
		SELECT vd.capability_id, vd.decision
		FROM verification_decisions vd
		JOIN scan_results sr ON sr.id = vd.scan_id
		WHERE sr.repo_id = ?
	`, repoID)
	if err != nil {
		return nil, fmt.Errorf("storage: get decision category stats for repo %d: %w", repoID, err)
	}
	defer dcRows.Close()
	for dcRows.Next() {
		var capID, decision string
		if err := dcRows.Scan(&capID, &decision); err != nil {
			return nil, fmt.Errorf("storage: scan decision category row: %w", err)
		}
		cat, ok := capIDToCategory[capID]
		if !ok {
			continue
		}
		cs := stats.ByCategory[string(cat)]
		if decision == "confirm" {
			cs.ConfirmCount++
		} else {
			cs.RevertCount++
		}
		stats.ByCategory[string(cat)] = cs
	}
	if err := dcRows.Err(); err != nil {
		return nil, fmt.Errorf("storage: decision category stats rows: %w", err)
	}

	return stats, nil
}

// buildCapCategoryMap returns a unique capID→category map across all scans for a repo.
func (s *SQLiteStore) buildCapCategoryMap(ctx context.Context, repoID int64) (map[string]contracts.CapCategory, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT capabilities_json FROM scan_results WHERE repo_id = ?`, repoID)
	if err != nil {
		return nil, fmt.Errorf("storage: fetch capabilities for repo %d: %w", repoID, err)
	}
	defer rows.Close()
	result := make(map[string]contracts.CapCategory)
	for rows.Next() {
		var capsJSON string
		if err := rows.Scan(&capsJSON); err != nil {
			return nil, fmt.Errorf("storage: scan capabilities_json row: %w", err)
		}
		var caps []contracts.Capability
		if err := json.Unmarshal([]byte(capsJSON), &caps); err != nil {
			continue // skip malformed rows
		}
		for _, cap := range caps {
			result[cap.ID] = cap.Category
		}
	}
	return result, rows.Err()
}

func (s *SQLiteStore) GetRecentScans(ctx context.Context, installationID int64, limit int) ([]RecentScan, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT sr.id, r.id, r.full_name, sr.pr_number, COALESCE(sr.head_branch,''),
		       sr.novel_count, sr.status, sr.scanned_at
		FROM scan_results sr
		JOIN repositories r ON r.id = sr.repo_id
		WHERE r.installation_id = ?
		ORDER BY sr.scanned_at DESC
		LIMIT ?
	`, installationID, limit)
	if err != nil {
		return nil, fmt.Errorf("storage: get recent scans for installation %d: %w", installationID, err)
	}
	defer rows.Close()

	var scans []RecentScan
	for rows.Next() {
		var rs RecentScan
		var scannedAt, status string
		if err := rows.Scan(&rs.ID, &rs.RepoID, &rs.FullName, &rs.PRNumber, &rs.HeadBranch,
			&rs.NovelCount, &status, &scannedAt); err != nil {
			return nil, fmt.Errorf("storage: scan recent scan row: %w", err)
		}
		rs.ScannedAt, _ = time.Parse(time.RFC3339, scannedAt)
		rs.Status = ScanStatus(status)
		scans = append(scans, rs)
	}
	return scans, rows.Err()
}

func (s *SQLiteStore) GetStatsByInstallation(ctx context.Context, installationID int64) (*InstallationStats, error) {
	stats := &InstallationStats{
		InstallationID: installationID,
		ByDeveloper:    make(map[string]DeveloperStats),
	}

	row := s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT r.id), COUNT(sr.id),
			COALESCE(SUM(sr.novel_count),0)
		FROM repositories r
		LEFT JOIN scan_results sr ON sr.repo_id = r.id
		WHERE r.installation_id = ?
	`, installationID)
	if err := row.Scan(&stats.TotalRepos, &stats.TotalScans, &stats.TotalCaps); err != nil {
		return nil, fmt.Errorf("storage: get installation scan stats %d: %w", installationID, err)
	}

	devRows, err := s.db.QueryContext(ctx, `
		SELECT vd.decided_by,
			SUM(CASE WHEN vd.decision = 'confirm' THEN 1 ELSE 0 END),
			SUM(CASE WHEN vd.decision = 'revert'  THEN 1 ELSE 0 END)
		FROM verification_decisions vd
		JOIN scan_results sr ON sr.id = vd.scan_id
		JOIN repositories r ON r.id = sr.repo_id
		WHERE r.installation_id = ?
		GROUP BY vd.decided_by
	`, installationID)
	if err != nil {
		return nil, fmt.Errorf("storage: get installation developer stats %d: %w", installationID, err)
	}
	defer devRows.Close()
	for devRows.Next() {
		var dev string
		var ds DeveloperStats
		if err := devRows.Scan(&dev, &ds.ConfirmCount, &ds.RevertCount); err != nil {
			return nil, fmt.Errorf("storage: scan installation developer stats row: %w", err)
		}
		stats.ByDeveloper[dev] = ds
		stats.ConfirmCount += ds.ConfirmCount
		stats.RevertCount += ds.RevertCount
	}
	if err := devRows.Err(); err != nil {
		return nil, fmt.Errorf("storage: installation developer stats rows: %w", err)
	}

	return stats, nil
}
