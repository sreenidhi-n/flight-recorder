package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tass-security/tass/internal/policy"
	"github.com/tass-security/tass/pkg/manifest"
)

func runPolicy(args []string) error {
	fs := flag.NewFlagSet("policy", flag.ContinueOnError)
	format := fs.String("format", "k8s", "output format: k8s or iam")
	app := fs.String("app", "myapp", "app label for podSelector (k8s) or Sid prefix (iam)")
	namespace := fs.String("namespace", "default", "Kubernetes namespace (k8s only)")
	output := fs.String("output", "", "write output to this file (default: stdout)")
	path := fs.String("path", ".", "path to repo containing tass.manifest.yaml")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: tass policy [flags]

Generate security policies from the TASS manifest.

Flags:`)
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Examples:
  tass policy --format k8s --app myapp
  tass policy --format iam --app myapp
  tass policy --format k8s --app myapp --output policy.yaml`)
	}

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("tass policy: %w", err)
	}

	if *format != "k8s" && *format != "iam" {
		return fmt.Errorf("tass policy: --format must be \"k8s\" or \"iam\", got %q", *format)
	}

	repoRoot, err := filepath.Abs(*path)
	if err != nil {
		return fmt.Errorf("tass policy: resolve path: %w", err)
	}

	manifestPath := filepath.Join(repoRoot, manifestFilename)
	m, err := manifest.Load(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("tass policy: manifest not found at %s — run 'tass init' first", manifestPath)
		}
		return fmt.Errorf("tass policy: load manifest: %w", err)
	}

	opts := policy.PolicyOpts{
		AppName:   *app,
		Namespace: *namespace,
	}

	var out []byte
	switch *format {
	case "k8s":
		out, err = policy.GenerateNetworkPolicy(m, opts)
	case "iam":
		out, err = policy.GenerateIAMPolicy(m, opts)
	}
	if err != nil {
		return fmt.Errorf("tass policy: generate %s policy: %w", *format, err)
	}

	if *output != "" {
		if err := os.WriteFile(*output, out, 0644); err != nil {
			return fmt.Errorf("tass policy: write output: %w", err)
		}
		fmt.Fprintf(os.Stderr, "✓  Written to %s\n", *output)
		return nil
	}

	_, err = os.Stdout.Write(out)
	return err
}
