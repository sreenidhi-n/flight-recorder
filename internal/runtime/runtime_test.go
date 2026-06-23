package runtime_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tass-security/tass/internal/runtime"
	"github.com/tass-security/tass/internal/runtime/parsers"
	"github.com/tass-security/tass/pkg/manifest"
)

// mockResolver maps IPs used in testdata to their expected hostnames.
var mockResolver = runtime.NewMapResolver(map[string]string{
	"151.101.1.195": "api.stripe.com",
	"203.0.113.1":   "evil.example.com",
})

func loadTestLog(t *testing.T) []parsers.Record {
	t.Helper()
	f, err := os.Open("testdata/sample.vpc.log")
	if err != nil {
		t.Fatalf("open testdata: %v", err)
	}
	defer f.Close()
	recs, err := parsers.ParseVPCFlow(f)
	if err != nil {
		t.Fatalf("parse vpc flow: %v", err)
	}
	return recs
}

func loadTestManifest(t *testing.T) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Load("testdata/sample.manifest.yaml")
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	return m
}

func TestVPCFlowParse_BasicFields(t *testing.T) {
	recs := loadTestLog(t)
	// REJECT record and private-IP record should be excluded
	// Expected: 2 records for 151.101.1.195:443 (both ACCEPT) + 1 for 203.0.113.1:443
	if len(recs) != 3 {
		t.Fatalf("expected 3 ACCEPT public records, got %d", len(recs))
	}
	for _, r := range recs {
		if r.Action != "ACCEPT" {
			t.Errorf("got non-ACCEPT record: %+v", r)
		}
		if r.DstAddr == "10.0.2.100" {
			t.Errorf("private IP should be filtered: %+v", r)
		}
	}
}

func TestVPCFlowParse_Deduplication(t *testing.T) {
	recs := loadTestLog(t)
	seen := make(map[string]int)
	for _, r := range recs {
		seen[r.DstAddr]++
	}
	if seen["151.101.1.195"] != 2 {
		t.Errorf("expected 2 records for 151.101.1.195, got %d", seen["151.101.1.195"])
	}
}

func TestExtractNetworkEndpoints(t *testing.T) {
	m := loadTestManifest(t)
	eps := runtime.ExtractNetworkEndpoints(m)
	if len(eps) == 0 {
		t.Fatal("expected at least one manifest endpoint, got none")
	}
	var found bool
	for _, ep := range eps {
		if ep.Pattern == "api.stripe.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected api.stripe.com in manifest endpoints, got: %v", eps)
	}
}

func TestDiff_WithDrift(t *testing.T) {
	recs := loadTestLog(t)
	m := loadTestManifest(t)

	report := runtime.Diff(recs, m, mockResolver, runtime.DiffConfig{
		LogFile:      "testdata/sample.vpc.log",
		ManifestFile: "testdata/sample.manifest.yaml",
	})

	if !report.HasDrift {
		t.Fatal("expected HasDrift=true (evil.example.com not in manifest)")
	}

	// evil.example.com must be in ObservedNotInManifest
	var foundEvil bool
	for _, e := range report.ObservedNotInManifest {
		if e.Hostname == "evil.example.com" || e.IP == "203.0.113.1" {
			foundEvil = true
		}
	}
	if !foundEvil {
		t.Errorf("evil.example.com / 203.0.113.1 should be in ObservedNotInManifest; got: %v",
			report.ObservedNotInManifest)
	}

	// api.stripe.com must be in ObservedInManifest
	var foundStripe bool
	for _, m := range report.ObservedInManifest {
		if m.Observed.Hostname == "api.stripe.com" || m.Observed.IP == "151.101.1.195" {
			foundStripe = true
		}
	}
	if !foundStripe {
		t.Errorf("api.stripe.com / 151.101.1.195 should be in ObservedInManifest; got: %v",
			report.ObservedInManifest)
	}
}

func TestDiff_NoDrift(t *testing.T) {
	// Only manifest-known traffic
	records := []parsers.Record{
		{DstAddr: "151.101.1.195", DstPort: 443, Protocol: 6, Action: "ACCEPT", Start: time.Now()},
	}
	m := loadTestManifest(t)
	report := runtime.Diff(records, m, mockResolver, runtime.DiffConfig{})
	if report.HasDrift {
		t.Errorf("expected no drift, got: %+v", report.ObservedNotInManifest)
	}
}

func TestDiff_SinceFilter(t *testing.T) {
	old := time.Now().Add(-48 * time.Hour)
	recent := time.Now().Add(-1 * time.Hour)
	records := []parsers.Record{
		{DstAddr: "203.0.113.1", DstPort: 443, Protocol: 6, Action: "ACCEPT", Start: old},
		{DstAddr: "151.101.1.195", DstPort: 443, Protocol: 6, Action: "ACCEPT", Start: recent},
	}
	m := loadTestManifest(t)
	// Only look at last 24h — old record should be excluded
	report := runtime.Diff(records, m, mockResolver, runtime.DiffConfig{Since: 24 * time.Hour})
	if report.HasDrift {
		t.Errorf("old drift record should be filtered by --since; got: %v", report.ObservedNotInManifest)
	}
	if report.ParsedRecords != 1 {
		t.Errorf("expected 1 parsed record within since window, got %d", report.ParsedRecords)
	}
}

func TestFormatText_ContainsSections(t *testing.T) {
	recs := loadTestLog(t)
	m := loadTestManifest(t)
	report := runtime.Diff(recs, m, mockResolver, runtime.DiffConfig{
		LogFile:      "sample.vpc.log",
		ManifestFile: "sample.manifest.yaml",
	})
	text := runtime.FormatText(report)
	for _, want := range []string{
		"endpoints_observed_in_manifest",
		"endpoints_observed_NOT_in_manifest",
		"endpoints_in_manifest_NEVER_observed",
		"evil.example.com",
		"DRIFT DETECTED",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text report missing %q", want)
		}
	}
}

func TestFormatJSON_Parseable(t *testing.T) {
	recs := loadTestLog(t)
	m := loadTestManifest(t)
	report := runtime.Diff(recs, m, mockResolver, runtime.DiffConfig{})
	b, err := runtime.FormatJSON(report)
	if err != nil {
		t.Fatalf("FormatJSON: %v", err)
	}
	if !strings.Contains(string(b), `"has_drift"`) {
		t.Errorf("JSON missing has_drift field")
	}
	if !strings.Contains(string(b), `"endpoints_observed_NOT_in_manifest"`) {
		t.Errorf("JSON missing drift section")
	}
}

// TestLooksLikeEndpoint_NumericPrefixHosts verifies that hostnames starting with
// a digit are accepted when not all labels are numeric (BP-4 fix).
func TestLooksLikeEndpoint_NumericPrefixHosts(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"1.api.example.com", true},   // digit-prefix but non-all-numeric → valid hostname
		{"0xdata.io", true},           // digit-prefix with non-numeric chars → valid
		{"123done.example.com", true}, // numeric first label, non-numeric labels follow
		{"1.2.3.4", false},            // IPv4 → reject
		{"1.0.0", false},              // semver-like → reject
		{"v1.2.3", false},             // semver with v prefix → reject
		{"api.stripe.com", true},      // normal hostname → accept
		{"1api.example.com", true},    // starts with digit, label is mixed → accept
	}
	for _, tc := range cases {
		got := runtime.LooksLikeEndpoint(tc.host)
		if got != tc.want {
			t.Errorf("LooksLikeEndpoint(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}
