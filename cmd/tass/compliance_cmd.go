package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tass-security/tass/internal/compliance"
	"github.com/tass-security/tass/internal/storage"
)

// runCompliance implements: tass compliance repo <name> [flags]
//
// Exit codes:
//
//	0  — success
//	1  — usage/runtime error
//	2  — audit chain broken (report generated but not trustworthy — exit 2 per spec)
func runCompliance(args []string) (int, error) {
	if len(args) < 2 || args[0] != "repo" {
		printComplianceUsage()
		return 1, nil
	}

	repoFullName := args[1]
	framework := "all"
	format := "md"
	dbPath := "tass.db"
	outputPath := ""
	var since *time.Time

	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--framework":
			i++
			if i >= len(args) {
				return 1, fmt.Errorf("--framework requires a value")
			}
			framework = strings.ToLower(args[i])
		case "--format":
			i++
			if i >= len(args) {
				return 1, fmt.Errorf("--format requires a value")
			}
			format = strings.ToLower(args[i])
		case "--db":
			i++
			if i >= len(args) {
				return 1, fmt.Errorf("--db requires a value")
			}
			dbPath = args[i]
		case "--output":
			i++
			if i >= len(args) {
				return 1, fmt.Errorf("--output requires a value")
			}
			outputPath = args[i]
		case "--since":
			i++
			if i >= len(args) {
				return 1, fmt.Errorf("--since requires a value")
			}
			t, err := time.Parse("2006-01-02", args[i])
			if err != nil {
				t, err = time.Parse(time.RFC3339, args[i])
			}
			if err != nil {
				return 1, fmt.Errorf("--since: invalid date %q (use YYYY-MM-DD or RFC3339)", args[i])
			}
			since = &t
		case "--help", "-h":
			printComplianceUsage()
			return 0, nil
		}
	}

	switch framework {
	case "soc2", "iso27001", "nist80053", "all":
	default:
		return 1, fmt.Errorf("unknown framework %q; must be soc2, iso27001, nist80053, or all", framework)
	}
	switch format {
	case "md", "json", "pdf":
	default:
		return 1, fmt.Errorf("unknown format %q; must be md, json, or pdf", format)
	}

	store, err := storage.Open(dbPath)
	if err != nil {
		return 1, fmt.Errorf("open database %q: %w", dbPath, err)
	}
	defer store.Close()

	gen := compliance.NewGenerator(store, version)
	report, genErr := gen.Generate(context.Background(), repoFullName, framework, since)

	// genErr may be ErrChainBroken — we still render the report but exit 2 per spec.
	if genErr != nil && !errors.Is(genErr, compliance.ErrChainBroken) {
		return 1, genErr
	}

	// Prominently flag a broken chain (spec: "fail loudly").
	if errors.Is(genErr, compliance.ErrChainBroken) {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "╔══════════════════════════════════════════════════════════╗")
		fmt.Fprintln(os.Stderr, "║  ⚠  AUDIT CHAIN INTEGRITY FAILURE                      ║")
		fmt.Fprintln(os.Stderr, "║  The tamper-evident hash chain is broken.               ║")
		fmt.Fprintln(os.Stderr, "║  This report MUST NOT be submitted as compliance        ║")
		fmt.Fprintln(os.Stderr, "║  evidence.                                              ║")
		fmt.Fprintln(os.Stderr, "╚══════════════════════════════════════════════════════════╝")
		fmt.Fprintln(os.Stderr, "")
	}

	var out []byte
	switch format {
	case "json":
		out, err = report.ToJSON()
	case "pdf":
		out, err = report.ToPDF()
	default:
		out = []byte(report.ToMarkdown())
	}
	if err != nil {
		return 1, fmt.Errorf("render %s: %w", format, err)
	}

	if outputPath != "" {
		if err := os.WriteFile(outputPath, out, 0644); err != nil {
			return 1, fmt.Errorf("write output: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Report written to %s (%d bytes)\n", outputPath, len(out))
	} else {
		if _, err := os.Stdout.Write(out); err != nil {
			return 1, fmt.Errorf("write stdout: %w", err)
		}
	}

	if errors.Is(genErr, compliance.ErrChainBroken) {
		return 2, nil
	}
	return 0, nil
}

func printComplianceUsage() {
	fmt.Fprintf(os.Stderr, `Usage: tass compliance repo <owner/repo> [flags]

Flags:
  --framework  soc2|iso27001|nist80053|all  (default: all)
  --format     md|json|pdf                   (default: md)
  --since      YYYY-MM-DD                    (restrict to scans after date)
  --db         PATH                          (SQLite DB path, default: tass.db)
  --output     FILE                          (write to file instead of stdout)

Frameworks:
  soc2       SOC 2 (AICPA TSP 100, 2017 TSC / 2022 PoF)
  iso27001   ISO/IEC 27001:2022 Annex A
  nist80053  NIST SP 800-53 Rev 5

Exit codes: 0=ok, 1=error, 2=audit chain broken (report generated but not trustworthy)
`)
}
