package runtime

import (
	"encoding/json"
	"fmt"
	"strings"
)

// FormatText renders a DiffReport as a human-readable terminal table.
func FormatText(r DiffReport) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Runtime Drift Report\n")
	fmt.Fprintf(&b, "Generated: %s\n", r.GeneratedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(&b, "Log:       %s\n", r.LogFile)
	fmt.Fprintf(&b, "Manifest:  %s\n", r.ManifestFile)
	fmt.Fprintf(&b, "Records:   %d parsed, %d unique destinations\n\n",
		r.ParsedRecords, r.UniqueIPs)

	// Section 1: observed and in manifest
	fmt.Fprintf(&b, "━━━ endpoints_observed_in_manifest (%d) ━━━\n", len(r.ObservedInManifest))
	if len(r.ObservedInManifest) == 0 {
		fmt.Fprintf(&b, "  (none)\n")
	} else {
		fmt.Fprintf(&b, "  %-40s %6s  %s\n", "Endpoint", "Port", "Matched Capability")
		fmt.Fprintf(&b, "  %-40s %6s  %s\n", strings.Repeat("─", 40), "──────", strings.Repeat("─", 30))
		for _, m := range r.ObservedInManifest {
			endpoint := m.Observed.Effective()
			fmt.Fprintf(&b, "  ✓ %-38s %6d  %s\n", endpoint, m.Observed.Port, m.CapName)
		}
	}
	fmt.Fprintln(&b)

	// Section 2: drift — observed but NOT in manifest
	if r.HasDrift {
		fmt.Fprintf(&b, "━━━ endpoints_observed_NOT_in_manifest (%d) ⚠  DRIFT DETECTED ━━━\n",
			len(r.ObservedNotInManifest))
	} else {
		fmt.Fprintf(&b, "━━━ endpoints_observed_NOT_in_manifest (%d) ━━━\n",
			len(r.ObservedNotInManifest))
	}
	if len(r.ObservedNotInManifest) == 0 {
		fmt.Fprintf(&b, "  (none — no drift)\n")
	} else {
		fmt.Fprintf(&b, "  %-40s %6s  %s\n", "Endpoint", "Port", "Hits")
		fmt.Fprintf(&b, "  %-40s %6s  %s\n", strings.Repeat("─", 40), "──────", "────")
		for _, e := range r.ObservedNotInManifest {
			endpoint := effectiveHost(e)
			raw := ""
			if e.Hostname != "" && e.IP != e.Hostname {
				raw = fmt.Sprintf(" (%s)", e.IP)
			}
			fmt.Fprintf(&b, "  ✗ %-38s %6d  ×%d%s\n", endpoint, e.Port, e.HitCount, raw)
		}
	}
	fmt.Fprintln(&b)

	// Section 3: in manifest but never observed (possibly dead capabilities)
	fmt.Fprintf(&b, "━━━ endpoints_in_manifest_NEVER_observed (%d) ━━━\n",
		len(r.ManifestNeverObserved))
	if len(r.ManifestNeverObserved) == 0 {
		fmt.Fprintf(&b, "  (none — all manifest endpoints seen in logs)\n")
	} else {
		for _, e := range r.ManifestNeverObserved {
			fmt.Fprintf(&b, "  ? %-40s  %s\n", e.Pattern, e.CapName)
		}
	}
	fmt.Fprintln(&b)

	if r.HasDrift {
		fmt.Fprintf(&b, "Result: DRIFT DETECTED — %d unrecognised endpoint(s) found\n",
			len(r.ObservedNotInManifest))
	} else {
		fmt.Fprintf(&b, "Result: OK — all observed endpoints are accounted for in the manifest\n")
	}

	return b.String()
}

// FormatJSON marshals a DiffReport to indented JSON.
func FormatJSON(r DiffReport) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
