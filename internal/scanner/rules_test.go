package scanner_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tass-security/tass/internal/scanner"
	"github.com/tass-security/tass/pkg/contracts"
)

// repoRulesDir returns the absolute path to the rules/ directory at the repo root.
// Tests in internal/scanner/ run with working directory set to the package directory,
// so we walk up two levels to reach the repo root.
func repoRulesDir(t *testing.T) string {
	t.Helper()
	here, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// internal/scanner/ → internal/ → repo root
	return filepath.Join(filepath.Dir(filepath.Dir(here)), "rules")
}

// TestLoadRules_LoadsAll verifies LoadRules loads all expected rules from the repo.
func TestLoadRules_LoadsAll(t *testing.T) {
	rules, err := scanner.LoadRules(repoRulesDir(t))
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// Verify all three languages are present.
	for _, lang := range []string{"go", "python", "javascript"} {
		langRules, ok := rules[lang]
		if !ok || len(langRules) == 0 {
			t.Errorf("language %q: no rules loaded", lang)
			continue
		}
		t.Logf("language %q: %d rules loaded", lang, len(langRules))
	}

	// Verify total rule count: 5 Go + 8 Python + 3 JS = 16
	total := 0
	for _, r := range rules {
		total += len(r)
	}
	if total < 16 {
		t.Errorf("total rules: got %d, want at least 16", total)
	}
}

// TestLoadRules_MetaValid verifies all loaded rules have valid metadata.
func TestLoadRules_MetaValid(t *testing.T) {
	rules, err := scanner.LoadRules(repoRulesDir(t))
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	validCategories := map[contracts.CapCategory]bool{
		contracts.CatNetworkAccess: true,
		contracts.CatDatabaseOp:   true,
		contracts.CatFileSystem:   true,
		contracts.CatExternalDep:  true,
		contracts.CatExternalAPI:  true,
		contracts.CatPrivilege:    true,
	}

	for lang, langRules := range rules {
		for _, r := range langRules {
			if r.Meta.Confidence <= 0 || r.Meta.Confidence > 1 {
				t.Errorf("[%s/%s] invalid confidence %f", lang, r.Name, r.Meta.Confidence)
			}
			if !validCategories[r.Meta.Category] {
				t.Errorf("[%s/%s] invalid category %q", lang, r.Name, r.Meta.Category)
			}
			if r.Meta.SymbolCapture == "" {
				t.Errorf("[%s/%s] empty symbol_capture", lang, r.Name)
			}
			if r.Meta.CapID == "" {
				t.Errorf("[%s/%s] empty cap_id", lang, r.Name)
			}
		}
	}
}

// TestLoadRules_MissingDir verifies an error is returned for a non-existent directory.
func TestLoadRules_MissingDir(t *testing.T) {
	_, err := scanner.LoadRules("/nonexistent/path/to/rules")
	if err == nil {
		t.Error("expected error for missing rules directory, got nil")
	}
}

// --- Per-language fixture detection tests ---

func newScannerFromRules(t *testing.T) *scanner.ASTScanner {
	t.Helper()
	s, err := scanner.NewASTScannerFromDir(repoRulesDir(t))
	if err != nil {
		t.Fatalf("NewASTScannerFromDir: %v", err)
	}
	return s
}

func TestRules_Go_DatabaseSQL(t *testing.T) {
	src := []byte(`package main

import (
	"database/sql"
	_ "github.com/lib/pq"
)

func main() {
	db, err := sql.Open("postgres", "host=localhost")
	if err != nil { panic(err) }
	defer db.Close()
}
`)
	s := newScannerFromRules(t)
	caps, err := s.ScanBytes(src, "main.go", "go")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}

	ids := capIDs(caps)
	if !ids["ast:go:database/sql:op:Open"] {
		t.Errorf("missing ast:go:database/sql:op:Open; got: %v", keys(ids))
	}
	for _, c := range caps {
		if c.Category != contracts.CatDatabaseOp {
			t.Errorf("%s: Category=%q, want database_operation", c.ID, c.Category)
		}
	}
}

// TestRules_Go_DatabaseSQL_NoBroadMatch verifies that generic method calls like
// cursor.Exec() (tree-sitter) are NOT matched by the database_sql rule.
func TestRules_Go_DatabaseSQL_NoBroadMatch(t *testing.T) {
	src := []byte(`package scanner

import sitter "github.com/smacker/go-tree-sitter"

func run(cursor *sitter.QueryCursor, query *sitter.Query, root *sitter.Node) {
	cursor.Exec(query, root)
}
`)
	s := newScannerFromRules(t)
	caps, err := s.ScanBytes(src, "ast.go", "go")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	for _, c := range caps {
		if c.ID == "ast:go:database/sql:op:Exec" {
			t.Errorf("cursor.Exec() should NOT match database_sql rule (false positive)")
		}
	}
}

func TestRules_Go_ExecCommand(t *testing.T) {
	src := []byte(`package main

import "os/exec"

func runGit(args ...string) error {
	cmd := exec.Command("git", args...)
	return cmd.Run()
}

func runWithContext(ctx context.Context, name string) {
	exec.CommandContext(ctx, name)
}
`)
	s := newScannerFromRules(t)
	caps, err := s.ScanBytes(src, "git.go", "go")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}

	ids := capIDs(caps)
	if !ids["ast:go:os/exec:subprocess:Command"] {
		t.Errorf("missing ast:go:os/exec:subprocess:Command; got: %v", keys(ids))
	}
	if !ids["ast:go:os/exec:subprocess:CommandContext"] {
		t.Errorf("missing ast:go:os/exec:subprocess:CommandContext; got: %v", keys(ids))
	}
	for _, c := range caps {
		if c.Category != contracts.CatPrivilege {
			t.Errorf("%s: Category=%q, want privilege_pattern", c.ID, c.Category)
		}
	}
}

func TestRules_Go_OSFile(t *testing.T) {
	src := []byte(`package main

import "os"

func main() {
	f, err := os.Create("/tmp/output.txt")
	if err != nil { panic(err) }
	defer f.Close()

	if err := os.WriteFile("/tmp/data.bin", []byte("hello"), 0644); err != nil {
		panic(err)
	}
}
`)
	s := newScannerFromRules(t)
	caps, err := s.ScanBytes(src, "main.go", "go")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}

	ids := capIDs(caps)
	if !ids["ast:go:os:file:Create"] {
		t.Errorf("missing ast:go:os:file:Create; got: %v", keys(ids))
	}
	if !ids["ast:go:os:file:WriteFile"] {
		t.Errorf("missing ast:go:os:file:WriteFile; got: %v", keys(ids))
	}
}

func TestRules_Go_NetListen(t *testing.T) {
	src := []byte(`package main

import "net"

func main() {
	ln, err := net.Listen("tcp", ":8080")
	if err != nil { panic(err) }
	defer ln.Close()
}
`)
	s := newScannerFromRules(t)
	caps, err := s.ScanBytes(src, "main.go", "go")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}

	ids := capIDs(caps)
	if !ids["ast:go:net:socket:Listen"] {
		t.Errorf("missing ast:go:net:socket:Listen; got: %v", keys(ids))
	}
}

func TestRules_Go_CleanFile(t *testing.T) {
	src := []byte(`package math

func Add(a, b int) int { return a + b }
func Mul(a, b int) int { return a * b }
`)
	s := newScannerFromRules(t)
	caps, err := s.ScanBytes(src, "math.go", "go")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	if len(caps) != 0 {
		t.Errorf("clean Go file: got %d capabilities, want 0: %v", len(caps), capIDs(caps))
	}
}

func TestRules_Python_Requests(t *testing.T) {
	src := []byte(`import requests

def fetch_user(user_id):
    resp = requests.get(f"https://api.example.com/users/{user_id}")
    resp.raise_for_status()
    return resp.json()

def create_charge(amount):
    return requests.post("https://api.stripe.com/v1/charges", data={"amount": amount})
`)
	s := newScannerFromRules(t)
	caps, err := s.ScanBytes(src, "api.py", "python")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}

	ids := capIDs(caps)
	if !ids["ast:python:requests:client:get"] {
		t.Errorf("missing ast:python:requests:client:get; got: %v", keys(ids))
	}
	if !ids["ast:python:requests:client:post"] {
		t.Errorf("missing ast:python:requests:client:post; got: %v", keys(ids))
	}
}

func TestRules_Python_Sqlite3(t *testing.T) {
	src := []byte(`import sqlite3

conn = sqlite3.connect("users.db")
cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY)")
conn.commit()
`)
	s := newScannerFromRules(t)
	caps, err := s.ScanBytes(src, "db.py", "python")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}

	ids := capIDs(caps)
	if !ids["ast:python:sqlite3:db:connect"] {
		t.Errorf("missing ast:python:sqlite3:db:connect; got: %v", keys(ids))
	}
}

func TestRules_Python_OpenFile(t *testing.T) {
	src := []byte(`def save_report(data):
    with open("report.csv", "w") as f:
        f.write(data)
`)
	s := newScannerFromRules(t)
	caps, err := s.ScanBytes(src, "report.py", "python")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}

	ids := capIDs(caps)
	if !ids["ast:python:builtins:file:open"] {
		t.Errorf("missing ast:python:builtins:file:open; got: %v", keys(ids))
	}
}

func TestRules_Python_CleanFile(t *testing.T) {
	src := []byte(`def add(a, b):
    return a + b

def greet(name):
    return f"Hello, {name}!"
`)
	s := newScannerFromRules(t)
	caps, err := s.ScanBytes(src, "utils.py", "python")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	if len(caps) != 0 {
		t.Errorf("clean Python file: got %d capabilities, want 0: %v", len(caps), capIDs(caps))
	}
}

func TestRules_JavaScript_Fetch(t *testing.T) {
	src := []byte(`async function getData(url) {
  const resp = await fetch("https://api.example.com/data");
  return resp.json();
}
`)
	s := newScannerFromRules(t)
	caps, err := s.ScanBytes(src, "api.js", "javascript")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}

	ids := capIDs(caps)
	if !ids["ast:javascript:http:client:fetch"] {
		t.Errorf("missing ast:javascript:http:client:fetch; got: %v", keys(ids))
	}
}

func TestRules_JavaScript_FS(t *testing.T) {
	src := []byte(`const fs = require('fs');

function saveOutput(data) {
  fs.writeFile('output.json', JSON.stringify(data), (err) => {
    if (err) throw err;
  });
}
`)
	s := newScannerFromRules(t)
	caps, err := s.ScanBytes(src, "storage.js", "javascript")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}

	ids := capIDs(caps)
	if !ids["ast:javascript:fs:file:writeFile"] {
		t.Errorf("missing ast:javascript:fs:file:writeFile; got: %v", keys(ids))
	}
}

func TestRules_JavaScript_HTTPServer(t *testing.T) {
	src := []byte(`const http = require('http');
const express = require('express');

const server = http.createServer((req, res) => {
  res.end('Hello');
});

const app = express();
`)
	s := newScannerFromRules(t)
	caps, err := s.ScanBytes(src, "server.js", "javascript")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}

	ids := capIDs(caps)
	if !ids["ast:javascript:http:server:createServer"] {
		t.Errorf("missing ast:javascript:http:server:createServer; got: %v", keys(ids))
	}
	if !ids["ast:javascript:http:server:express"] {
		t.Errorf("missing ast:javascript:http:server:express; got: %v", keys(ids))
	}
}

func TestRules_JavaScript_CleanFile(t *testing.T) {
	src := []byte(`function add(a, b) { return a + b; }
function greet(name) { return "Hello, " + name; }
`)
	s := newScannerFromRules(t)
	caps, err := s.ScanBytes(src, "utils.js", "javascript")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	if len(caps) != 0 {
		t.Errorf("clean JS file: got %d capabilities, want 0: %v", len(caps), capIDs(caps))
	}
}

// TestRules_Python_Boto3 verifies boto3.client() and boto3.resource() are detected.
// Snippet mirrors the direct boto3 usage pattern from requirements.txt consumers.
func TestRules_Python_Boto3(t *testing.T) {
	src := []byte(`import boto3

s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')

def upload_file(bucket, key, body):
    s3.put_object(Bucket=bucket, Key=key, Body=body)
`)
	s := newScannerFromRules(t)
	caps, err := s.ScanBytes(src, "aws_tools.py", "python")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}

	ids := capIDs(caps)
	if !ids["ast:python:boto3:client:client"] {
		t.Errorf("missing ast:python:boto3:client:client; got: %v", keys(ids))
	}
	if !ids["ast:python:boto3:client:resource"] {
		t.Errorf("missing ast:python:boto3:client:resource; got: %v", keys(ids))
	}
	for _, c := range caps {
		if c.ID == "ast:python:boto3:client:client" || c.ID == "ast:python:boto3:client:resource" {
			if c.Category != contracts.CatNetworkAccess {
				t.Errorf("%s: Category=%q, want network_access", c.ID, c.Category)
			}
			if c.Confidence != 0.95 {
				t.Errorf("%s: Confidence=%f, want 0.95", c.ID, c.Confidence)
			}
		}
	}
}

// TestRules_Python_Boto3_NoBroadMatch verifies that unrelated attribute calls
// (e.g. s3.put_object()) are NOT matched by the boto3 rule.
func TestRules_Python_Boto3_NoBroadMatch(t *testing.T) {
	src := []byte(`import boto3

s3 = boto3.client('s3')
s3.put_object(Bucket='bucket', Key='k', Body=b'data')
s3.get_object(Bucket='bucket', Key='k')
`)
	s := newScannerFromRules(t)
	caps, err := s.ScanBytes(src, "s3.py", "python")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	// Only boto3.client() should match — put_object/get_object are s3.* calls, not boto3.*
	ids := capIDs(caps)
	if ids["ast:python:boto3:client:put_object"] {
		t.Error("s3.put_object() should NOT match boto3 rule (false positive)")
	}
	if ids["ast:python:boto3:client:get_object"] {
		t.Error("s3.get_object() should NOT match boto3 rule (false positive)")
	}
}

// TestRules_Python_StrandsAgent verifies Agent() instantiation is detected.
// Snippet is drawn from workshop/module_01_first_agent/agent.py.
func TestRules_Python_StrandsAgent(t *testing.T) {
	src := []byte(`from strands import Agent
from shared.model import model

SYSTEM_PROMPT = "You are SupportBot, a helpful customer support agent."

agent = Agent(system_prompt=SYSTEM_PROMPT, model=model)
`)
	s := newScannerFromRules(t)
	caps, err := s.ScanBytes(src, "agent.py", "python")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}

	ids := capIDs(caps)
	if !ids["ast:python:strands:agent:Agent"] {
		t.Errorf("missing ast:python:strands:agent:Agent; got: %v", keys(ids))
	}
	for _, c := range caps {
		if c.ID == "ast:python:strands:agent:Agent" {
			if c.Category != contracts.CatExternalAPI {
				t.Errorf("%s: Category=%q, want external_api", c.ID, c.Category)
			}
			if c.Confidence != 0.9 {
				t.Errorf("%s: Confidence=%f, want 0.9", c.ID, c.Confidence)
			}
		}
	}
}

// TestRules_Python_StrandsAgent_MultiAgent verifies that multiple Agent()
// calls in the same file (workshop/module_04_multi_agent style) deduplicate to one capability.
func TestRules_Python_StrandsAgent_MultiAgent(t *testing.T) {
	src := []byte(`from strands import Agent
from shared.model import model

order_agent = Agent(system_prompt="You handle orders.", model=model)
catalog_agent = Agent(system_prompt="You handle catalog lookups.", model=model)
triage_agent = Agent(system_prompt="You triage requests.", model=model,
                     tools=[order_agent, catalog_agent])
`)
	s := newScannerFromRules(t)
	caps, err := s.ScanBytes(src, "triage_agent.py", "python")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	// All three Agent() calls resolve to the same ID — deduplicated to exactly 1.
	ids := capIDs(caps)
	if !ids["ast:python:strands:agent:Agent"] {
		t.Errorf("missing ast:python:strands:agent:Agent; got: %v", keys(ids))
	}
	if len(ids) > 1 {
		// Should only have the one strands cap (plus any from open_file if used, but we don't here)
		for id := range ids {
			if id != "ast:python:strands:agent:Agent" {
				t.Logf("note: additional capability detected: %s", id)
			}
		}
	}
	count := 0
	for _, c := range caps {
		if c.ID == "ast:python:strands:agent:Agent" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("Agent() deduplication: got %d occurrences of strands:agent:Agent, want 1", count)
	}
}

// TestRules_Python_FastMCP verifies FastMCP() constructor and @mcp.tool() decorator are detected.
// Snippet is drawn from workshop/module_02_tools_mcp/mcp_server.py.
func TestRules_Python_FastMCP(t *testing.T) {
	src := []byte(`from fastmcp import FastMCP

mcp = FastMCP(
    name="TechStore Catalog Server",
    instructions="MCP server providing access to TechStore's product catalog.",
)

@mcp.tool()
def get_product_details(sku: str) -> dict:
    """Get detailed information about a product by SKU."""
    return {"sku": sku, "name": "Widget"}

@mcp.tool()
def list_all_products(category: str = "") -> list:
    """List all products."""
    return []

@mcp.resource("catalog://categories")
def list_categories() -> str:
    """List all available product categories."""
    return "Electronics, Furniture"
`)
	s := newScannerFromRules(t)
	caps, err := s.ScanBytes(src, "mcp_server.py", "python")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}

	ids := capIDs(caps)
	if !ids["ast:python:fastmcp:server:FastMCP"] {
		t.Errorf("missing ast:python:fastmcp:server:FastMCP; got: %v", keys(ids))
	}
	if !ids["ast:python:fastmcp:server:tool"] {
		t.Errorf("missing ast:python:fastmcp:server:tool; got: %v", keys(ids))
	}
	if !ids["ast:python:fastmcp:server:resource"] {
		t.Errorf("missing ast:python:fastmcp:server:resource; got: %v", keys(ids))
	}
	for _, c := range caps {
		if c.Category != contracts.CatNetworkAccess {
			t.Errorf("%s: Category=%q, want network_access", c.ID, c.Category)
		}
	}
}

// TestRules_Python_OpenTelemetry verifies TracerProvider() and set_tracer_provider() are detected.
// Snippet mirrors the opentelemetry-sdk setup pattern from the workshop requirements.
func TestRules_Python_OpenTelemetry(t *testing.T) {
	src := []byte(`from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

exporter = OTLPSpanExporter(endpoint="http://localhost:4317", insecure=True)
provider = TracerProvider()
provider.add_span_processor(BatchSpanProcessor(exporter))
trace.set_tracer_provider(provider)
`)
	s := newScannerFromRules(t)
	caps, err := s.ScanBytes(src, "telemetry.py", "python")
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}

	ids := capIDs(caps)
	if !ids["ast:python:otel:tracing:TracerProvider"] {
		t.Errorf("missing ast:python:otel:tracing:TracerProvider; got: %v", keys(ids))
	}
	if !ids["ast:python:otel:tracing:set_tracer_provider"] {
		t.Errorf("missing ast:python:otel:tracing:set_tracer_provider; got: %v", keys(ids))
	}
	for _, c := range caps {
		if c.ID == "ast:python:otel:tracing:TracerProvider" || c.ID == "ast:python:otel:tracing:set_tracer_provider" {
			if c.Category != contracts.CatNetworkAccess {
				t.Errorf("%s: Category=%q, want network_access", c.ID, c.Category)
			}
			if c.Confidence != 0.85 {
				t.Errorf("%s: Confidence=%f, want 0.85", c.ID, c.Confidence)
			}
		}
	}
}

// --- helpers ---

func capIDs(caps []contracts.Capability) map[string]bool {
	m := make(map[string]bool, len(caps))
	for _, c := range caps {
		m[c.ID] = true
	}
	return m
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
