package server

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/tass-security/tass/internal/runtime"
	"github.com/tass-security/tass/internal/runtime/parsers"
	"github.com/tass-security/tass/pkg/manifest"
)

const maxLogUploadBytes = 50 * 1024 * 1024 // 50 MiB

// RuntimeVerifyHandler handles POST /api/runtime-verify.
//
// Accepts a multipart form with:
//   - log      (file field)   — log file bytes
//   - manifest (file field)   — tass.manifest.yaml bytes
//   - format   (text field)   — "vpc-flow" (default)
//
// Log contents are processed entirely in-memory and never written to disk or
// the database.
//
// Returns a JSON DiffReport on success.
type RuntimeVerifyHandler struct{}

func NewRuntimeVerifyHandler() *RuntimeVerifyHandler {
	return &RuntimeVerifyHandler{}
}

func (h *RuntimeVerifyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(maxLogUploadBytes); err != nil {
		// Fallback: try as regular form
		if ferr := r.ParseForm(); ferr != nil {
			jsonError(w, fmt.Sprintf("parse form: %v", err), http.StatusBadRequest)
			return
		}
	}

	logFormat := r.FormValue("format")
	if logFormat == "" {
		logFormat = "vpc-flow"
	}
	if logFormat != "vpc-flow" {
		jsonError(w, fmt.Sprintf("unsupported log format %q (only vpc-flow supported)", logFormat),
			http.StatusBadRequest)
		return
	}

	logBytes, err := readFormFile(r, "log")
	if err != nil {
		jsonError(w, "log field required: "+err.Error(), http.StatusBadRequest)
		return
	}

	manifestBytes, err := readFormFile(r, "manifest")
	if err != nil {
		jsonError(w, "manifest field required: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Parse manifest — in-memory only.
	m, err := manifest.LoadBytes(manifestBytes)
	if err != nil {
		jsonError(w, "invalid manifest: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Parse log — in-memory only.
	var records []parsers.Record
	switch logFormat {
	case "vpc-flow":
		records, err = parsers.ParseVPCFlow(bytes.NewReader(logBytes))
	}
	if err != nil {
		jsonError(w, fmt.Sprintf("parse %s log: %v", logFormat, err), http.StatusBadRequest)
		return
	}

	// Resolve hostnames. 1 s timeout per lookup to keep API latency bounded.
	resolver := runtime.NewDNSResolver(time.Second)
	report := runtime.Diff(records, m, resolver, runtime.DiffConfig{
		LogFile:      "(uploaded)",
		ManifestFile: "(uploaded)",
	})

	b, err := runtime.FormatJSON(report)
	if err != nil {
		slog.Error("runtime-verify: marshal report", "error", err)
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if report.HasDrift {
		w.WriteHeader(http.StatusMultiStatus) // 207 — drift found but result is complete
	}
	_, _ = w.Write(b)
}

// readFormFile reads the named multipart field, falling back to a plain form value.
func readFormFile(r *http.Request, name string) ([]byte, error) {
	// Try multipart file field first.
	if r.MultipartForm != nil {
		if fhs, ok := r.MultipartForm.File[name]; ok && len(fhs) > 0 {
			fh := fhs[0]
			if fh.Size > maxLogUploadBytes {
				return nil, fmt.Errorf("file too large (%d bytes, max %d)", fh.Size, maxLogUploadBytes)
			}
			f, err := fh.Open()
			if err != nil {
				return nil, err
			}
			defer f.Close()
			return io.ReadAll(io.LimitReader(f, maxLogUploadBytes))
		}
	}
	// Fall back to plain text form value (useful for curl --data).
	val := r.FormValue(name)
	if val == "" {
		return nil, fmt.Errorf("field %q not found", name)
	}
	return []byte(val), nil
}
