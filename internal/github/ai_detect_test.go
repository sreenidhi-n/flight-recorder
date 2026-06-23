package github_test

import (
	"strings"
	"testing"

	gh "github.com/tass-security/tass/internal/github"
)

// --- DetectAI: author login heuristic ---

func TestDetectAI_KnownBotLogin_DependaBot(t *testing.T) {
	sig := gh.DetectAI("dependabot[bot]", nil, 0)
	if !sig.IsAIGenerated {
		t.Error("dependabot[bot] should be flagged as AI-generated")
	}
	assertSignalContains(t, sig, "dependabot[bot]")
}

func TestDetectAI_KnownBotLogin_ClaudeCode(t *testing.T) {
	sig := gh.DetectAI("claude-code", nil, 0)
	if !sig.IsAIGenerated {
		t.Error("claude-code should be flagged as AI-generated")
	}
}

func TestDetectAI_KnownBotLogin_Copilot(t *testing.T) {
	sig := gh.DetectAI("github-copilot[bot]", nil, 0)
	if !sig.IsAIGenerated {
		t.Error("github-copilot[bot] should be flagged")
	}
}

func TestDetectAI_KnownBotLogin_Sweep(t *testing.T) {
	sig := gh.DetectAI("sweep[bot]", nil, 0)
	if !sig.IsAIGenerated {
		t.Error("sweep[bot] should be flagged")
	}
}

func TestDetectAI_KnownBotLogin_Devin(t *testing.T) {
	sig := gh.DetectAI("devin-ai-integration[bot]", nil, 0)
	if !sig.IsAIGenerated {
		t.Error("devin-ai-integration[bot] should be flagged")
	}
}

func TestDetectAI_KnownBotLogin_Antigravity(t *testing.T) {
	sig := gh.DetectAI("antigravity", nil, 0)
	if !sig.IsAIGenerated {
		t.Error("antigravity should be flagged")
	}
}

func TestDetectAI_HumanAuthor_NotFlagged(t *testing.T) {
	sig := gh.DetectAI("alice", nil, 0)
	if sig.IsAIGenerated {
		t.Errorf("human login 'alice' should not be flagged; signals: %v", sig.Signals)
	}
}

func TestDetectAI_EmptyAuthor_NotFlagged(t *testing.T) {
	sig := gh.DetectAI("", nil, 0)
	if sig.IsAIGenerated {
		t.Errorf("empty login should not be flagged; signals: %v", sig.Signals)
	}
}

// --- DetectAI: commit message heuristic ---

func TestDetectAI_CommitMessage_CopilotCoAuthor(t *testing.T) {
	commits := []gh.CommitMeta{
		{Message: "Add payment handler\n\nCo-authored-by: GitHub Copilot <copilot@github.com>", AuthorLogin: "alice"},
	}
	sig := gh.DetectAI("alice", commits, 50)
	if !sig.IsAIGenerated {
		t.Error("Copilot co-author trailer should be flagged")
	}
	assertSignalContains(t, sig, "copilot")
}

func TestDetectAI_CommitMessage_ClaudeCoAuthor(t *testing.T) {
	commits := []gh.CommitMeta{
		{Message: "Refactor scanner\n\nCo-authored-by: Claude <noreply@anthropic.com>", AuthorLogin: "bob"},
	}
	sig := gh.DetectAI("bob", commits, 100)
	if !sig.IsAIGenerated {
		t.Error("Claude co-author trailer should be flagged")
	}
}

func TestDetectAI_CommitMessage_GeneratedByCursor(t *testing.T) {
	commits := []gh.CommitMeta{
		{Message: "feat: implement auth flow\n\nGenerated-By: Cursor", AuthorLogin: "carol"},
	}
	sig := gh.DetectAI("carol", commits, 200)
	if !sig.IsAIGenerated {
		t.Error("Generated-By: Cursor trailer should be flagged")
	}
}

func TestDetectAI_CommitMessage_AIGeneratedTag(t *testing.T) {
	commits := []gh.CommitMeta{
		{Message: "[AI Generated] Initial scaffold for payments module", AuthorLogin: "dave"},
	}
	sig := gh.DetectAI("dave", commits, 300)
	if !sig.IsAIGenerated {
		t.Error("[AI Generated] tag in commit message should be flagged")
	}
}

func TestDetectAI_CommitMessage_CleanHuman_NotFlagged(t *testing.T) {
	commits := []gh.CommitMeta{
		{Message: "fix: correct off-by-one in loop", AuthorLogin: "alice"},
		{Message: "test: add unit tests for parser", AuthorLogin: "alice"},
	}
	sig := gh.DetectAI("alice", commits, 80)
	if sig.IsAIGenerated {
		t.Errorf("clean human commits should not be flagged; signals: %v", sig.Signals)
	}
}

func TestDetectAI_CommitMessage_MultipleCommits_OneAI(t *testing.T) {
	commits := []gh.CommitMeta{
		{Message: "fix: typo in README", AuthorLogin: "alice"},
		{Message: "feat: add bulk export\n\nCo-authored-by: GitHub Copilot <copilot@github.com>", AuthorLogin: "alice"},
		{Message: "chore: update deps", AuthorLogin: "alice"},
	}
	sig := gh.DetectAI("alice", commits, 150)
	if !sig.IsAIGenerated {
		t.Error("one AI-attributed commit should flag the whole PR")
	}
}

// --- DetectAI: commit author login (can differ from PR author) ---

func TestDetectAI_CommitAuthorLogin_FlaggedWhenDifferentFromPRAuthor(t *testing.T) {
	// PR opened by a human, but one commit was authored by a bot.
	commits := []gh.CommitMeta{
		{Message: "initial commit", AuthorLogin: "claude-code"},
	}
	sig := gh.DetectAI("alice", commits, 50)
	if !sig.IsAIGenerated {
		t.Error("claude-code commit author should flag the PR even when PR author is human")
	}
	assertSignalContains(t, sig, "claude-code")
}

// --- DetectAI: velocity heuristic (informational only) ---

func TestDetectAI_VelocityOnly_NotFlagged(t *testing.T) {
	// Large diff alone should NOT set IsAIGenerated.
	sig := gh.DetectAI("alice", nil, 1500)
	if sig.IsAIGenerated {
		t.Errorf("velocity alone should not set IsAIGenerated; signals: %v", sig.Signals)
	}
	// But a signal should be recorded.
	if len(sig.Signals) == 0 {
		t.Error("expected velocity informational signal, got none")
	}
	assertSignalContains(t, sig, "lines changed")
}

func TestDetectAI_BelowVelocityThreshold_NoVelocitySignal(t *testing.T) {
	sig := gh.DetectAI("alice", nil, 499)
	if sig.IsAIGenerated {
		t.Error("below-threshold diff should not be flagged")
	}
	// No velocity signal expected.
	for _, s := range sig.Signals {
		if strings.Contains(s, "lines changed") {
			t.Errorf("velocity signal should not appear below threshold; got: %q", s)
		}
	}
}

func TestDetectAI_AIAuthorPlusLargeDiff_TwoSignals(t *testing.T) {
	// Both author and velocity fire; only one definitive signal needed.
	sig := gh.DetectAI("sweep[bot]", nil, 2000)
	if !sig.IsAIGenerated {
		t.Error("sweep[bot] should be flagged")
	}
	if len(sig.Signals) < 2 {
		t.Errorf("expected at least 2 signals (author + velocity), got %d: %v", len(sig.Signals), sig.Signals)
	}
}

// --- DetectAI: case insensitivity ---

func TestDetectAI_CaseInsensitiveLogin(t *testing.T) {
	for _, login := range []string{"Sweep[Bot]", "SWEEP[BOT]", "Sweep"} {
		sig := gh.DetectAI(login, nil, 0)
		if !sig.IsAIGenerated {
			t.Errorf("login %q should be case-insensitively flagged", login)
		}
	}
}

func TestDetectAI_CaseInsensitiveCommitMessage(t *testing.T) {
	commits := []gh.CommitMeta{
		{Message: "Co-Authored-By: GitHub Copilot <copilot@github.com>", AuthorLogin: "alice"},
	}
	sig := gh.DetectAI("alice", commits, 0)
	if !sig.IsAIGenerated {
		t.Error("commit message trailer matching should be case-insensitive")
	}
}

// --- AISignal zero value ---

func TestDetectAI_NoSignals_ZeroValue(t *testing.T) {
	sig := gh.DetectAI("alice", []gh.CommitMeta{
		{Message: "fix: normal commit", AuthorLogin: "alice"},
	}, 10)
	if sig.IsAIGenerated {
		t.Error("clean PR should have IsAIGenerated=false")
	}
	if len(sig.Signals) != 0 {
		t.Errorf("clean PR should have no signals, got: %v", sig.Signals)
	}
}

// --- helper ---

func assertSignalContains(t *testing.T, sig gh.AISignal, substr string) {
	t.Helper()
	for _, s := range sig.Signals {
		if strings.Contains(strings.ToLower(s), strings.ToLower(substr)) {
			return
		}
	}
	t.Errorf("expected a signal containing %q; got signals: %v", substr, sig.Signals)
}
