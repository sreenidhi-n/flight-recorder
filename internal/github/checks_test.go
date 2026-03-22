package github_test

import (
	"strings"
	"testing"

	gh "github.com/tass-security/tass/internal/github"
)

func TestCheckSummary_NoCapabilities(t *testing.T) {
	title, summary := gh.CheckSummary(0, "scan-001", "http://localhost:8080")
	if title != "No new capabilities detected" {
		t.Errorf("title: got %q", title)
	}
	if !strings.Contains(summary, "All clear") {
		t.Errorf("summary should mention 'All clear', got: %q", summary)
	}
}

func TestCheckSummary_OneCapability(t *testing.T) {
	title, summary := gh.CheckSummary(1, "scan-002", "http://localhost:8080")
	if !strings.Contains(title, "1 new capability") {
		t.Errorf("title should say '1 new capability', got: %q", title)
	}
	// singular — no "capabilities"
	if strings.Contains(title, "capabilities") {
		t.Errorf("title should be singular, got: %q", title)
	}
	if !strings.Contains(summary, "scan-002") {
		t.Errorf("summary should contain scan ID, got: %q", summary)
	}
	if !strings.Contains(summary, "http://localhost:8080") {
		t.Errorf("summary should contain base URL, got: %q", summary)
	}
}

func TestCheckSummary_ManyCapabilities(t *testing.T) {
	title, _ := gh.CheckSummary(3, "scan-003", "https://app.tass.dev")
	if !strings.Contains(title, "3 new capabilities") {
		t.Errorf("title: got %q", title)
	}
}
