package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/tass-security/tass/internal/storage"
	"github.com/tass-security/tass/pkg/contracts"
)

func runSeed(args []string) error {
	fs := flag.NewFlagSet("seed", flag.ContinueOnError)
	dbPath := fs.String("db", "tass.db", "path to SQLite database to seed")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return fmt.Errorf("tass seed: %w", err)
	}

	ctx := context.Background()
	store, err := storage.Open(*dbPath)
	if err != nil {
		return fmt.Errorf("tass seed: open storage: %w", err)
	}
	defer store.Close()

	// Idempotency: skip if demo data is already present.
	if existing, _ := store.GetScan(ctx, "demo-scan-pay-001"); existing != nil {
		fmt.Fprintln(os.Stderr, "seed: demo data already present — delete the database file to re-seed")
		return nil
	}

	now := time.Now().UTC()
	daysAgo := func(d int) time.Time { return now.AddDate(0, 0, -d) }

	// ── Installation ─────────────────────────────────────────────────────────
	if err := store.UpsertInstallation(ctx, storage.Installation{
		ID:             12345,
		AccountLogin:   "acme-corp",
		AccountType:    "Organization",
		InstalledAt:    daysAgo(30),
		AccessToken:    "ghs_demo_placeholder_not_real",
		TokenExpiresAt: now.Add(time.Hour),
	}); err != nil {
		return fmt.Errorf("tass seed: upsert installation: %w", err)
	}

	// ── Repositories ─────────────────────────────────────────────────────────
	for _, r := range []storage.Repository{
		{ID: 1001, InstallationID: 12345, FullName: "acme-corp/payments-service",
			DefaultBranch: "main", CreatedAt: daysAgo(30)},
		{ID: 1002, InstallationID: 12345, FullName: "acme-corp/ai-support-bot",
			DefaultBranch: "main", CreatedAt: daysAgo(20)},
	} {
		if err := store.UpsertRepository(ctx, r); err != nil {
			return fmt.Errorf("tass seed: upsert repo %s: %w", r.FullName, err)
		}
	}

	// ── Capability helpers ────────────────────────────────────────────────────
	dep := func(id, name string) contracts.Capability {
		return contracts.Capability{
			ID: id, Name: name,
			Category: contracts.CatExternalDep, Source: contracts.LayerDependency,
			Confidence: 1.0, RawEvidence: name,
		}
	}
	ast := func(id, name string, cat contracts.CapCategory, file string, line int, conf float64) contracts.Capability {
		return contracts.Capability{
			ID: id, Name: name, Category: cat, Source: contracts.LayerAST,
			Location: contracts.CodeLocation{File: file, Line: line},
			Confidence: conf, RawEvidence: id,
		}
	}

	// ── Scans ─────────────────────────────────────────────────────────────────

	// Scan 1 — payments-service PR #42 (verified, 13 days ago)
	caps1 := []contracts.Capability{
		dep("layer0:go:stripe-go:v76", "stripe-go v76"),
		ast("ast:go:net/http:client:Post", "HTTP client via net/http (Post)",
			contracts.CatNetworkAccess, "internal/payments/client.go", 34, 0.95),
		ast("ast:go:database/sql:op:Open", "Database connection via database/sql (Open)",
			contracts.CatDatabaseOp, "internal/storage/db.go", 18, 0.95),
	}
	if err := store.SaveScan(ctx, storage.ScanResult{
		ID: "demo-scan-pay-001", RepoID: 1001, InstallationID: 12345,
		PRNumber: 42, HeadBranch: "feat/stripe-integration",
		CommitSHA: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		BaseSHA:   "0000000000000000000000000000000000000000",
		ScannedAt: daysAgo(13), ScanDurationMS: 312,
		Capabilities: caps1, NovelCount: 3,
		Status: storage.StatusVerified, CheckRunID: 9001001, CommentID: 7001001,
	}); err != nil {
		return fmt.Errorf("tass seed: save scan 1: %w", err)
	}

	// Scan 2 — payments-service PR #45 (pending, 8 days ago)
	caps2 := []contracts.Capability{
		dep("layer0:go:aws-sdk-go:v2.34", "aws-sdk-go v2.34"),
		dep("layer0:go:pgx:v5.7", "pgx v5.7"),
		ast("ast:go:os:file:WriteFile", "Filesystem write via os.WriteFile",
			contracts.CatFileSystem, "internal/reports/exporter.go", 72, 0.9),
		ast("ast:go:net:socket:Listen", "TCP listener via net.Listen",
			contracts.CatNetworkAccess, "cmd/worker/main.go", 29, 0.95),
		ast("ast:go:os/exec:subprocess:Command", "Subprocess via exec.Command",
			contracts.CatPrivilege, "internal/scanner/git.go", 55, 0.9),
	}
	if err := store.SaveScan(ctx, storage.ScanResult{
		ID: "demo-scan-pay-002", RepoID: 1001, InstallationID: 12345,
		PRNumber: 45, HeadBranch: "feat/async-worker",
		CommitSHA: "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
		BaseSHA:   "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		ScannedAt: daysAgo(8), ScanDurationMS: 489,
		Capabilities: caps2, NovelCount: 5,
		Status: storage.StatusPending, CheckRunID: 9001002, CommentID: 7001002,
	}); err != nil {
		return fmt.Errorf("tass seed: save scan 2: %w", err)
	}

	// Scan 3 — payments-service PR #47 (verified, 3 days ago)
	caps3 := []contracts.Capability{
		ast("ast:go:net/http:client:Get", "HTTP client via net/http (Get)",
			contracts.CatNetworkAccess, "internal/webhooks/sender.go", 41, 0.95),
		ast("ast:go:database/sql:op:QueryContext", "DB query via database/sql (QueryContext)",
			contracts.CatDatabaseOp, "internal/storage/ledger.go", 103, 0.95),
	}
	if err := store.SaveScan(ctx, storage.ScanResult{
		ID: "demo-scan-pay-003", RepoID: 1001, InstallationID: 12345,
		PRNumber: 47, HeadBranch: "fix/webhook-retry",
		CommitSHA: "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
		BaseSHA:   "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
		ScannedAt: daysAgo(3), ScanDurationMS: 201,
		Capabilities: caps3, NovelCount: 2,
		Status: storage.StatusVerified, CheckRunID: 9001003, CommentID: 7001003,
	}); err != nil {
		return fmt.Errorf("tass seed: save scan 3: %w", err)
	}

	// Scan 4 — ai-support-bot PR #12 (pending, 6 days ago)
	caps4 := []contracts.Capability{
		dep("layer0:python:openai:v1.68.0", "openai v1.68.0"),
		dep("layer0:python:strands-agents:v1.0.0", "strands-agents v1.0.0"),
		ast("ast:python:boto3:client:client", "AWS SDK service connection via boto3 (client)",
			contracts.CatNetworkAccess, "shared/model.py", 12, 0.95),
		ast("ast:python:strands:agent:Agent", "Strands AI agent instantiation (Agent)",
			contracts.CatExternalAPI, "module_01_first_agent/agent.py", 44, 0.9),
		ast("ast:python:fastmcp:server:FastMCP", "FastMCP server or tool registration (FastMCP)",
			contracts.CatNetworkAccess, "module_02_tools_mcp/mcp_server.py", 24, 0.9),
		ast("ast:python:fastmcp:server:tool", "FastMCP server or tool registration (tool)",
			contracts.CatNetworkAccess, "module_02_tools_mcp/mcp_server.py", 38, 0.9),
		ast("ast:python:requests:client:post", "HTTP client via requests library (post)",
			contracts.CatNetworkAccess, "module_02_tools_mcp/tools.py", 89, 0.95),
		ast("ast:python:sqlite3:db:connect", "SQLite database connection (connect)",
			contracts.CatDatabaseOp, "module_03_memory/agent_with_memory.py", 31, 0.95),
	}
	if err := store.SaveScan(ctx, storage.ScanResult{
		ID: "demo-scan-ai-001", RepoID: 1002, InstallationID: 12345,
		PRNumber: 12, HeadBranch: "feat/mcp-tools",
		CommitSHA: "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
		BaseSHA:   "0000000000000000000000000000000000000000",
		ScannedAt: daysAgo(6), ScanDurationMS: 734,
		Capabilities: caps4, NovelCount: 8,
		Status: storage.StatusPending, CheckRunID: 9002001, CommentID: 7002001,
	}); err != nil {
		return fmt.Errorf("tass seed: save scan 4: %w", err)
	}

	// Scan 5 — ai-support-bot PR #14 (verified, 1 day ago)
	caps5 := []contracts.Capability{
		dep("layer0:python:fastmcp:v0.1.0", "fastmcp v0.1.0"),
		dep("layer0:python:boto3:v1.35.0", "boto3 v1.35.0"),
		ast("ast:python:otel:tracing:TracerProvider", "OpenTelemetry tracing setup (TracerProvider)",
			contracts.CatNetworkAccess, "module_06_deploy/app.py", 15, 0.85),
		ast("ast:python:otel:tracing:set_tracer_provider", "OpenTelemetry tracing setup (set_tracer_provider)",
			contracts.CatNetworkAccess, "module_06_deploy/app.py", 18, 0.85),
	}
	if err := store.SaveScan(ctx, storage.ScanResult{
		ID: "demo-scan-ai-002", RepoID: 1002, InstallationID: 12345,
		PRNumber: 14, HeadBranch: "feat/observability",
		CommitSHA: "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
		BaseSHA:   "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
		ScannedAt: daysAgo(1), ScanDurationMS: 418,
		Capabilities: caps5, NovelCount: 4,
		Status: storage.StatusVerified, CheckRunID: 9002002, CommentID: 7002002,
	}); err != nil {
		return fmt.Errorf("tass seed: save scan 5: %w", err)
	}

	// ── Verification decisions ────────────────────────────────────────────────

	type dec struct {
		id       string
		scanID   string
		capID    string
		decision contracts.VerificationDecision
		by       string
		at       time.Time
	}
	decisions := []dec{
		// Scan 1 — all confirmed (stripe integration, 12–13 days ago)
		{"demo-dec-001", "demo-scan-pay-001", "layer0:go:stripe-go:v76", contracts.DecisionConfirm, "alice", daysAgo(12)},
		{"demo-dec-002", "demo-scan-pay-001", "ast:go:net/http:client:Post", contracts.DecisionConfirm, "bob", daysAgo(12)},
		{"demo-dec-003", "demo-scan-pay-001", "ast:go:database/sql:op:Open", contracts.DecisionConfirm, "alice", daysAgo(11)},

		// Scan 2 — mixed (async worker, 6–7 days ago)
		{"demo-dec-004", "demo-scan-pay-002", "layer0:go:aws-sdk-go:v2.34", contracts.DecisionConfirm, "carol", daysAgo(7)},
		{"demo-dec-005", "demo-scan-pay-002", "layer0:go:pgx:v5.7", contracts.DecisionConfirm, "carol", daysAgo(7)},
		{"demo-dec-006", "demo-scan-pay-002", "ast:go:os:file:WriteFile", contracts.DecisionConfirm, "bob", daysAgo(6)},
		{"demo-dec-007", "demo-scan-pay-002", "ast:go:os/exec:subprocess:Command", contracts.DecisionRevert, "bob", daysAgo(6)},

		// Scan 3 — all confirmed (webhook retry, 2 days ago)
		{"demo-dec-008", "demo-scan-pay-003", "ast:go:net/http:client:Get", contracts.DecisionConfirm, "alice", daysAgo(2)},
		{"demo-dec-009", "demo-scan-pay-003", "ast:go:database/sql:op:QueryContext", contracts.DecisionConfirm, "alice", daysAgo(2)},

		// Scan 4 — partial (mcp-tools, 4–5 days ago)
		{"demo-dec-010", "demo-scan-ai-001", "layer0:python:openai:v1.68.0", contracts.DecisionConfirm, "carol", daysAgo(5)},
		{"demo-dec-011", "demo-scan-ai-001", "layer0:python:strands-agents:v1.0.0", contracts.DecisionConfirm, "carol", daysAgo(5)},
		{"demo-dec-012", "demo-scan-ai-001", "ast:python:boto3:client:client", contracts.DecisionConfirm, "bob", daysAgo(4)},
		{"demo-dec-013", "demo-scan-ai-001", "ast:python:strands:agent:Agent", contracts.DecisionConfirm, "alice", daysAgo(4)},
		{"demo-dec-014", "demo-scan-ai-001", "ast:python:fastmcp:server:FastMCP", contracts.DecisionRevert, "alice", daysAgo(4)},

		// Scan 5 — all confirmed (observability, today)
		{"demo-dec-015", "demo-scan-ai-002", "layer0:python:fastmcp:v0.1.0", contracts.DecisionConfirm, "bob", daysAgo(0)},
		{"demo-dec-016", "demo-scan-ai-002", "layer0:python:boto3:v1.35.0", contracts.DecisionConfirm, "carol", daysAgo(0)},
		{"demo-dec-017", "demo-scan-ai-002", "ast:python:otel:tracing:TracerProvider", contracts.DecisionConfirm, "carol", daysAgo(0)},
		{"demo-dec-018", "demo-scan-ai-002", "ast:python:otel:tracing:set_tracer_provider", contracts.DecisionConfirm, "alice", daysAgo(0)},
	}

	for _, d := range decisions {
		if err := store.SaveDecision(ctx, storage.VerificationDecision{
			ID:           d.id,
			ScanID:       d.scanID,
			CapabilityID: d.capID,
			Decision:     d.decision,
			DecidedBy:    d.by,
			DecidedAt:    d.at,
		}); err != nil {
			return fmt.Errorf("tass seed: save decision %s: %w", d.id, err)
		}
	}

	// ── Summary ───────────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("  ✓ 1 installation    (id: 12345, acme-corp)")
	fmt.Println("  ✓ 2 repositories    (payments-service, ai-support-bot)")
	fmt.Println("  ✓ 5 scan results    (3 payments, 2 ai-support-bot)")
	fmt.Println("  ✓ 18 decisions      (alice: 7, bob: 6, carol: 5)")
	fmt.Println()
	fmt.Println("  Dashboard: http://localhost:8080/dashboard?installation_id=12345")
	fmt.Println("  Repo view: http://localhost:8080/dashboard/repo?repo_id=1001")
	fmt.Println()
	return nil
}
