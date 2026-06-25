package github

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/tass-security/tass/pkg/contracts"
)

// fuzzRequiredCategories is the set of capability categories that must have a
// corresponding FuzzX function in the adjacent _test.go file.
var fuzzRequiredCategories = map[contracts.CapCategory]bool{
	contracts.CatDatabaseOp:   true,
	contracts.CatExternalAPI:  true,
	contracts.CatLLMExecution: true,
}

// CheckFuzzPresence inspects each high-risk capability's adjacent _test.go file
// on the PR head branch. For CatDatabaseOp, CatExternalAPI, and CatLLMExecution
// capabilities, it fetches the sibling test file from headSHA and looks for a
// func Fuzz… declaration. If no fuzz function is found (or the file is absent),
// the capability's RequiresFuzzing field is set to true.
//
// AP-3 invariant: FetchFileContent returns (nil, nil) for 404s. We treat that as
// "test file absent → RequiresFuzzing=true". Non-nil errors (network, auth, etc.)
// are logged and skipped — we never penalise the developer for infrastructure issues.
//
// AP-2: the loop is sequential because a PR typically has ≤10 high-risk capabilities;
// a bounded worker pool would add complexity without measurable benefit here.
func CheckFuzzPresence(
	ctx context.Context,
	app *App,
	token, owner, repo, headSHA string,
	caps []contracts.Capability,
) []contracts.Capability {
	log := slog.With("repo", owner+"/"+repo, "head_sha", headSHA[:min8(headSHA)])

	for i := range caps {
		if !fuzzRequiredCategories[caps[i].Category] {
			continue
		}
		sourceFile := caps[i].Location.File
		if sourceFile == "" {
			continue
		}

		testFile := adjacentTestFile(sourceFile)
		content, err := app.FetchFileContent(ctx, token, owner, repo, testFile, headSHA)
		if err != nil {
			// Operational error (network, auth) — do not flag RequiresFuzzing.
			log.Warn("fuzz_check: fetch test file failed, skipping",
				"test_file", testFile, "error", err)
			continue
		}

		if content == nil {
			// AP-3: (nil, nil) means the file genuinely does not exist at headSHA.
			log.Info("fuzz_check: no test file found, flagging RequiresFuzzing",
				"source_file", sourceFile, "test_file", testFile)
			caps[i].RequiresFuzzing = true
			continue
		}

		if !hasFuzzFunction(content) {
			log.Info("fuzz_check: test file exists but has no FuzzX function",
				"test_file", testFile, "cap_id", caps[i].ID)
			caps[i].RequiresFuzzing = true
		}
	}

	return caps
}

// adjacentTestFile converts a Go source path to its corresponding test file path.
// "internal/server/handler.go" → "internal/server/handler_test.go"
// Non-Go files are left as-is with "_test" appended before the extension.
func adjacentTestFile(sourceFile string) string {
	ext := filepath.Ext(sourceFile)
	return strings.TrimSuffix(sourceFile, ext) + "_test" + ext
}

// hasFuzzFunction returns true when content contains at least one Go fuzz test
// function declaration (i.e. "func Fuzz" substring).
func hasFuzzFunction(content []byte) bool {
	return bytes.Contains(content, []byte("func Fuzz"))
}

// min8 returns the minimum of n and 8, used for safe SHA log truncation.
func min8(s string) int {
	if len(s) < 8 {
		return len(s)
	}
	return 8
}
