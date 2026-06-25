package mitigation

import (
	"strings"
	"testing"

	"github.com/tass-security/tass/pkg/contracts"
)

func TestGenerateFuzzStub_HTTPHandler(t *testing.T) {
	cap := contracts.Capability{
		ID:       "ast:go:llm:http:Post",
		Name:     "LLM provider API HTTP call (Post)",
		Category: contracts.CatLLMExecution,
		Location: contracts.CodeLocation{File: "internal/service/llm.go", Line: 42},
	}
	out := GenerateFuzzStub(cap)
	if out == "" {
		t.Fatal("expected non-empty stub for CatLLMExecution")
	}
	for _, want := range []string{
		"func FuzzLLMProviderAPIHTTPCallPost",
		"httptest.NewRecorder",
		"httptest.NewRequest",
		"' OR 1=1 --",
		"../../../etc/passwd",
		"<script>alert(1)</script>",
		"prompt injection",
		"w.Code >= 500",
		"package service_test",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stub missing %q\nfull output:\n%s", want, out)
		}
	}
}

func TestGenerateFuzzStub_DatabaseOp(t *testing.T) {
	cap := contracts.Capability{
		ID:       "ast:go:database/sql:Query",
		Name:     "SQL query execution (Query)",
		Category: contracts.CatDatabaseOp,
		Location: contracts.CodeLocation{File: "internal/storage/storage.go", Line: 10},
	}
	out := GenerateFuzzStub(cap)
	if out == "" {
		t.Fatal("expected non-empty stub for CatDatabaseOp")
	}
	for _, want := range []string{
		"func FuzzSQLQueryExecutionQuery",
		"' OR 1=1 --",
		"'; DROP TABLE users; --",
		"context.Background",
		"package storage_test",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stub missing %q\nfull output:\n%s", want, out)
		}
	}
}

func TestGenerateFuzzStub_ExternalAPI(t *testing.T) {
	cap := contracts.Capability{
		ID:       "ast:go:net/http:client:Get",
		Name:     "External API call (Get)",
		Category: contracts.CatExternalAPI,
		Location: contracts.CodeLocation{File: "pkg/client/client.go", Line: 5},
	}
	out := GenerateFuzzStub(cap)
	if !strings.Contains(out, "httptest") {
		t.Error("expected httptest in external_api stub")
	}
	if !strings.Contains(out, "package client_test") {
		t.Errorf("expected package client_test, got:\n%s", out)
	}
}

func TestGenerateFuzzStub_NonFuzzCategory(t *testing.T) {
	cap := contracts.Capability{
		ID:       "ast:go:os:file:Open",
		Name:     "File open (Open)",
		Category: contracts.CatFileSystem,
		Location: contracts.CodeLocation{File: "main.go"},
	}
	out := GenerateFuzzStub(cap)
	if out != "" {
		t.Errorf("expected empty stub for non-fuzz category, got %q", out)
	}
}

func TestCapToFuncName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"HTTP GET (api.openai.com)", "HTTPGETApiOpenaiCom"},
		{"SQL query execution (Query)", "SQLQueryExecutionQuery"},
		{"", "Cap"},
	}
	for _, tc := range cases {
		got := capToFuncName(tc.in)
		if got != tc.want {
			t.Errorf("capToFuncName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPackageFromFile(t *testing.T) {
	cases := []struct {
		file, want string
	}{
		{"internal/server/handler.go", "server"},
		{"main.go", "main"},
		{"pkg/client/client.go", "client"},
	}
	for _, tc := range cases {
		got := packageFromFile(tc.file)
		if got != tc.want {
			t.Errorf("packageFromFile(%q) = %q, want %q", tc.file, got, tc.want)
		}
	}
}
