//go:build ignore

// This file exists solely to demonstrate a contract violation for testing.
// It introduces exec.Command which is forbidden by tass.contract.yaml.
package testdata

import "os/exec"

func runShellCommand(cmd string) error {
	return exec.Command("sh", "-c", cmd).Run()
}
