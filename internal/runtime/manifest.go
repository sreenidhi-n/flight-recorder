package runtime

import (
	"path"
	"regexp"
	"strings"

	"github.com/tass-security/tass/pkg/contracts"
	"github.com/tass-security/tass/pkg/manifest"
)

// ManifestEndpoint is a hostname pattern extracted from a manifest entry.
type ManifestEndpoint struct {
	Pattern  string                `json:"pattern"`
	CapID    string                `json:"cap_id"`
	CapName  string                `json:"cap_name"`
	Category contracts.CapCategory `json:"category"`
}

// hostnameRe matches hostnames (including wildcards) embedded in free-form text.
var hostnameRe = regexp.MustCompile(
	`(?i)(?:\*\.)?(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}`,
)

// urlSchemeRe strips scheme prefixes so we can find the host part.
var urlSchemeRe = regexp.MustCompile(`^https?://`)

// ExtractNetworkEndpoints returns all hostname patterns found in the manifest
// entries with category network_access or external_api.
// Patterns are extracted from: RawEvidence, Name, and the Note field.
func ExtractNetworkEndpoints(m *manifest.Manifest) []ManifestEndpoint {
	var out []ManifestEndpoint
	seen := make(map[string]bool)

	for _, entry := range m.Capabilities {
		if entry.Category != contracts.CatNetworkAccess && entry.Category != contracts.CatExternalAPI {
			continue
		}
		patterns := hostnamesFromEntry(entry)
		for _, p := range patterns {
			key := entry.ID + "|" + p
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, ManifestEndpoint{
				Pattern:  p,
				CapID:    entry.ID,
				CapName:  entry.Name,
				Category: entry.Category,
			})
		}
	}
	return out
}

func hostnamesFromEntry(entry manifest.ManifestEntry) []string {
	var candidates []string
	candidates = append(candidates, entry.Name, entry.Note)

	var found []string
	seen := make(map[string]bool)
	for _, text := range candidates {
		// Strip URL scheme so the regex picks up the host part cleanly.
		text = urlSchemeRe.ReplaceAllString(text, "")
		// Strip path/query fragments (first / after the host)
		if idx := strings.IndexByte(text, '/'); idx != -1 {
			text = text[:idx]
		}
		for _, h := range hostnameRe.FindAllString(text, -1) {
			h = strings.ToLower(h)
			// Skip obviously non-endpoint strings like "layer1_ast" or file extensions
			if LooksLikeEndpoint(h) && !seen[h] {
				seen[h] = true
				found = append(found, h)
			}
		}
	}
	return found
}

// LooksLikeEndpoint filters out false positives from the hostname regex.
// Exported for use in tests.
func LooksLikeEndpoint(h string) bool {
	// Reject single-label names (no dot → not a hostname)
	if !strings.Contains(h, ".") {
		return false
	}
	// Reject common file extensions that aren't hostnames
	for _, ext := range []string{".go", ".py", ".js", ".ts", ".yaml", ".json", ".toml", ".txt", ".mod"} {
		if strings.HasSuffix(h, ext) {
			return false
		}
	}
	// Reject dotted-decimal version strings (e.g. "1.2.3", "v1.0.0") where
	// every dot-separated label is purely numeric (after stripping a leading "v").
	// We do NOT reject hostnames that merely start with a digit, such as
	// "1.api.example.com" or "0xdata.io" — only reject when ALL labels are numeric.
	parts := strings.Split(h, ".")
	allNumeric := true
	for _, p := range parts {
		stripped := strings.TrimLeft(p, "v")
		if stripped == "" {
			allNumeric = false
			break
		}
		for _, c := range stripped {
			if c < '0' || c > '9' {
				allNumeric = false
				break
			}
		}
		if !allNumeric {
			break
		}
	}
	if allNumeric {
		return false
	}
	return true
}

// MatchesManifest returns the first ManifestEndpoint that matches the given
// hostname, or nil if no match is found.
// Matching order: exact match → glob match → subdomain suffix match.
func MatchesManifest(hostname string, endpoints []ManifestEndpoint) *ManifestEndpoint {
	if hostname == "" {
		return nil
	}
	hostname = strings.ToLower(hostname)
	for i, ep := range endpoints {
		pat := strings.ToLower(ep.Pattern)
		if pat == hostname {
			return &endpoints[i]
		}
		// Glob: *.stripe.com should match api.stripe.com
		if matched, _ := path.Match(pat, hostname); matched {
			return &endpoints[i]
		}
		// Suffix: "stripe.com" in manifest matches "api.stripe.com" in logs
		if strings.HasSuffix(hostname, "."+pat) {
			return &endpoints[i]
		}
		// Suffix: "api.stripe.com" in manifest covers "api.stripe.com" subdomain
		if strings.HasSuffix(hostname, pat) && strings.HasPrefix(pat, ".") {
			return &endpoints[i]
		}
	}
	return nil
}
