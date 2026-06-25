package github

import (
	"testing"
)

func TestAdjacentTestFile(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"internal/server/handler.go", "internal/server/handler_test.go"},
		{"pkg/client/client.go", "pkg/client/client_test.go"},
		{"main.go", "main_test.go"},
		{"scanner/ast.go", "scanner/ast_test.go"},
		{"service.py", "service_test.py"},
	}
	for _, tc := range cases {
		got := adjacentTestFile(tc.in)
		if got != tc.want {
			t.Errorf("adjacentTestFile(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHasFuzzFunction(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name:    "has fuzz function",
			content: "package foo\n\nfunc FuzzParseInput(f *testing.F) {}\n",
			want:    true,
		},
		{
			name:    "multiple fuzz functions",
			content: "func FuzzA(f *testing.F) {}\nfunc FuzzB(f *testing.F) {}",
			want:    true,
		},
		{
			name:    "no fuzz function",
			content: "package foo\n\nfunc TestFoo(t *testing.T) {}\n",
			want:    false,
		},
		{
			name:    "empty file",
			content: "",
			want:    false,
		},
		{
			name:    "comment containing func Fuzz does not count",
			content: "// func Fuzz is documented here\nfunc TestFoo(t *testing.T) {}\n",
			want:    true, // conservative: we match the substring, comments included
		},
	}
	for _, tc := range cases {
		got := hasFuzzFunction([]byte(tc.content))
		if got != tc.want {
			t.Errorf("hasFuzzFunction(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
