package main

import (
	"fmt"
	"os"
)

const version = "v3.0.0-dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "--version", "-v", "version":
		fmt.Printf("tass %s\n", version)
	case "init":
		fmt.Fprintln(os.Stderr, "tass init: not yet implemented")
		os.Exit(1)
	case "scan":
		fmt.Fprintln(os.Stderr, "tass scan: not yet implemented")
		os.Exit(1)
	case "serve":
		fmt.Fprintln(os.Stderr, "tass serve: not yet implemented")
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "tass: unknown command %q\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: tass <command> [flags]

Commands:
  init     Generate tass.manifest.yaml from the current repository
  scan     Scan for new capabilities against a base branch
  serve    Start the TASS web server (production)
  version  Print version and exit

Run 'tass <command> --help' for more information.
`)
}
