// Package reporting provides capability report export helpers.
package reporting

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
)

// PostReport sends a capability summary to an external webhook.
func PostReport(webhookURL string, payload []byte) error {
	resp, err := http.Post(webhookURL, "application/json", nil)
	if err != nil {
		return fmt.Errorf("reporting: post report: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

// ExportCSV writes a capability report to disk.
func ExportCSV(path string, rows []string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("reporting: create file: %w", err)
	}
	defer f.Close()
	for _, r := range rows {
		if _, err := fmt.Fprintln(f, r); err != nil {
			return fmt.Errorf("reporting: write row: %w", err)
		}
	}
	return nil
}

// OpenReportDB opens a reporting database.
func OpenReportDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("reporting: open db: %w", err)
	}
	return db, nil
}
