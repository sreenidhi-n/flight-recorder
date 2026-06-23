package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tass-security/tass/internal/runtime"
	"github.com/tass-security/tass/internal/runtime/parsers"
	"github.com/tass-security/tass/pkg/manifest"
)

// runVerifyRuntime implements `tass verify-runtime`.
// Returns (exitCode, error):
//   - (0, nil)  → no drift
//   - (1, nil)  → drift detected (endpoints not in manifest)
//   - (1, err)  → operational failure
func runVerifyRuntime(args []string) (int, error) {
	fs := flag.NewFlagSet("verify-runtime", flag.ContinueOnError)
	logsPath := fs.String("logs", "", "path to log file")
	logFormat := fs.String("log-format", "vpc-flow", "log format: vpc-flow")
	manifestPath := fs.String("manifest", "tass.manifest.yaml", "path to tass.manifest.yaml")
	sinceStr := fs.String("since", "", "only consider records from the last N (e.g. 7d, 24h, 30m)")
	format := fs.String("format", "text", "output format: text or json")
	dnsTimeout := fs.Duration("dns-timeout", 2*time.Second, "timeout per DNS reverse lookup")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: tass verify-runtime [flags]

Diff a log file against the TASS manifest to detect runtime drift.
Exits 0 if all observed endpoints are in the manifest; 1 if drift is found.

Flags:`)
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Examples:
  tass verify-runtime --logs vpc.log --log-format vpc-flow --manifest tass.manifest.yaml
  tass verify-runtime --logs vpc.log --since 7d --format json`)
	}

	if err := fs.Parse(args); err != nil {
		return 1, fmt.Errorf("verify-runtime: %w", err)
	}

	if *logsPath == "" {
		fs.Usage()
		return 1, fmt.Errorf("--logs is required")
	}

	if *logFormat != "vpc-flow" {
		return 1, fmt.Errorf("unsupported log format %q (only vpc-flow supported in v1)", *logFormat)
	}

	if *format != "text" && *format != "json" {
		return 1, fmt.Errorf("--format must be \"text\" or \"json\"")
	}

	// Parse --since duration
	var sinceDur time.Duration
	if *sinceStr != "" {
		var err error
		sinceDur, err = parseSince(*sinceStr)
		if err != nil {
			return 1, fmt.Errorf("--since: %w", err)
		}
	}

	// Load manifest
	m, err := manifest.Load(*manifestPath)
	if err != nil {
		return 1, fmt.Errorf("verify-runtime: load manifest: %w", err)
	}

	// Parse log file — in-memory only, never persisted
	f, err := os.Open(*logsPath)
	if err != nil {
		return 1, fmt.Errorf("verify-runtime: open logs: %w", err)
	}
	defer f.Close()

	var records []parsers.Record
	switch *logFormat {
	case "vpc-flow":
		records, err = parsers.ParseVPCFlow(f)
	}
	if err != nil {
		return 1, fmt.Errorf("verify-runtime: parse %s logs: %w", *logFormat, err)
	}

	resolver := runtime.NewDNSResolver(*dnsTimeout)
	report := runtime.Diff(records, m, resolver, runtime.DiffConfig{
		LogFile:      *logsPath,
		ManifestFile: *manifestPath,
		Since:        sinceDur,
	})

	// Output
	switch *format {
	case "json":
		b, err := runtime.FormatJSON(report)
		if err != nil {
			return 1, fmt.Errorf("verify-runtime: marshal json: %w", err)
		}
		fmt.Println(string(b))
	default:
		fmt.Print(runtime.FormatText(report))
	}

	if report.HasDrift {
		return 1, nil
	}
	return 0, nil
}

// parseSince converts strings like "7d", "24h", "30m" to time.Duration.
func parseSince(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}

	// If it already parses as a Go duration ("24h", "30m") use that.
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}

	// Handle shorthand: "7d" = 7 days.
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}

	return 0, fmt.Errorf("unrecognised duration %q (use e.g. 7d, 24h, 30m)", s)
}
