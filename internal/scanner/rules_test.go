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

	// Verify total rule count: 4 Go + 4 Python + 3 JS = 11
	total := 0
	for _, r := range rules {
		total += len(r)
	}
	if total < 11 {
		t.Errorf("total rules: got %d, want at least 11", total)
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
	rows, err := db.Query("SELECT id FROM users WHERE active = $1", true)
	if err != nil { panic(err) }
	defer rows.Close()
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
	if !ids["ast:go:database/sql:op:Query"] {
		t.Errorf("missing ast:go:database/sql:op:Query; got: %v", keys(ids))
	}
	for _, c := range caps {
		if c.Category != contracts.CatDatabaseOp {
			t.Errorf("%s: Category=%q, want database_operation", c.ID, c.Category)
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
