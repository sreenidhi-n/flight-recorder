// Package storage handles local file I/O for report generation and temp artifacts.
package storage

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const reportDir = "/var/acme/reports"

// WriteReport writes a generated report to disk and returns the file path.
func WriteReport(name string, content []byte) (string, error) {
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		return "", fmt.Errorf("storage.WriteReport: mkdir: %w", err)
	}

	stamp := time.Now().UTC().Format("20060102-150405")
	path := filepath.Join(reportDir, fmt.Sprintf("%s-%s.pdf", name, stamp))

	if err := os.WriteFile(path, content, 0644); err != nil {
		return "", fmt.Errorf("storage.WriteReport: write: %w", err)
	}
	return path, nil
}

// ArchiveReports compresses old reports into a tarball for long-term storage.
func ArchiveReports(outDir string) error {
	stamp := time.Now().UTC().Format("20060102")
	archive := filepath.Join(outDir, "reports-"+stamp+".tar.gz")

	cmd := exec.Command("tar", "-czf", archive, reportDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("storage.ArchiveReports: tar: %w — %s", err, out)
	}
	return nil
}

// CleanTemp removes all files older than maxAge from the OS temp directory
// whose names match the given prefix.
func CleanTemp(prefix string, maxAge time.Duration) (int, error) {
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		return 0, fmt.Errorf("storage.CleanTemp: readdir: %w", err)
	}

	deleted := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if len(name) < len(prefix) || name[:len(prefix)] != prefix {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if time.Since(info.ModTime()) > maxAge {
			path := filepath.Join(os.TempDir(), name)
			if err := os.Remove(path); err == nil {
				deleted++
			}
		}
	}
	return deleted, nil
}

// CreateTempFile creates a named temporary file and returns it open for writing.
func CreateTempFile(prefix, ext string) (*os.File, error) {
	f, err := os.CreateTemp("", prefix+"*"+ext)
	if err != nil {
		return nil, fmt.Errorf("storage.CreateTempFile: %w", err)
	}
	return f, nil
}
