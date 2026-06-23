package runtime

import (
	"sort"
	"strings"
	"time"

	"github.com/tass-security/tass/internal/runtime/parsers"
	"github.com/tass-security/tass/pkg/manifest"
)

// ObservedEndpoint is a unique egress destination seen in logs.
type ObservedEndpoint struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"` // resolved; empty if DNS failed
	Port     int    `json:"port"`
	HitCount int    `json:"hit_count"`
}

// Effective returns the hostname if resolved, otherwise the raw IP.
func (e ObservedEndpoint) Effective() string {
	if e.Hostname != "" {
		return e.Hostname
	}
	return e.IP
}

// MatchedEndpoint pairs an observed endpoint with the manifest entry it matched.
type MatchedEndpoint struct {
	Observed ObservedEndpoint `json:"observed"`
	CapID    string           `json:"cap_id"`
	CapName  string           `json:"cap_name"`
	Pattern  string           `json:"matched_pattern"`
}

// DiffReport is the complete output of a runtime vs manifest comparison.
type DiffReport struct {
	GeneratedAt   time.Time `json:"generated_at"`
	LogFile       string    `json:"log_file"`
	ManifestFile  string    `json:"manifest_file"`
	ParsedRecords int       `json:"parsed_records"`
	UniqueIPs     int       `json:"unique_ips"`
	HasDrift      bool      `json:"has_drift"`

	ObservedInManifest    []MatchedEndpoint  `json:"endpoints_observed_in_manifest"`
	ObservedNotInManifest []ObservedEndpoint `json:"endpoints_observed_NOT_in_manifest"`
	ManifestNeverObserved []ManifestEndpoint `json:"endpoints_in_manifest_NEVER_observed"`
}

// DiffConfig carries parameters for the Diff call.
type DiffConfig struct {
	LogFile      string
	ManifestFile string
	Since        time.Duration // 0 = no time filter
}

// Diff compares observed log records against the manifest and produces a DiffReport.
// resolver is used to map destination IPs to hostnames; pass NewDNSResolver or a
// MapResolver for tests.
func Diff(records []parsers.Record, m *manifest.Manifest, resolver Resolver, cfg DiffConfig) DiffReport {
	report := DiffReport{
		GeneratedAt:           time.Now().UTC(),
		LogFile:               cfg.LogFile,
		ManifestFile:          cfg.ManifestFile,
		ObservedInManifest:    []MatchedEndpoint{},
		ObservedNotInManifest: []ObservedEndpoint{},
		ManifestNeverObserved: []ManifestEndpoint{},
	}

	// Time filter
	var since time.Time
	if cfg.Since > 0 {
		since = time.Now().UTC().Add(-cfg.Since)
	}

	// Deduplicate records into ObservedEndpoints keyed by IP:port.
	type key struct {
		ip   string
		port int
	}
	obs := make(map[key]*ObservedEndpoint)
	parsed := 0
	for _, rec := range records {
		if !since.IsZero() && rec.Start.Before(since) {
			continue
		}
		parsed++
		k := key{rec.DstAddr, rec.DstPort}
		if _, ok := obs[k]; !ok {
			obs[k] = &ObservedEndpoint{
				IP:   rec.DstAddr,
				Port: rec.DstPort,
			}
		}
		obs[k].HitCount++
	}
	report.ParsedRecords = parsed
	report.UniqueIPs = len(obs)

	// Resolve hostnames in parallel with a bounded worker pool (AP-2 fix).
	// Unbounded goroutine fan-out caused goroutine storms on large VPC flow logs
	// (>10,000 unique IPs). A buffered-channel semaphore caps concurrency.
	const dnsWorkers = 50
	type resolved struct {
		k        key
		hostname string
	}
	ch := make(chan resolved, len(obs))
	sem := make(chan struct{}, dnsWorkers)
	for k, ep := range obs {
		go func(k key, ep *ObservedEndpoint) {
			sem <- struct{}{}
			hostname := resolver.Lookup(ep.IP)
			<-sem
			ch <- resolved{k: k, hostname: hostname}
		}(k, ep)
	}
	for range obs {
		r := <-ch
		obs[r.k].Hostname = r.hostname
	}

	// Extract manifest endpoint patterns.
	manifestEndpoints := ExtractNetworkEndpoints(m)

	// Track which manifest endpoints were matched.
	manifestMatched := make(map[string]bool) // key: CapID+Pattern

	// Classify each observed endpoint.
	for _, ep := range obs {
		hostname := ep.Hostname
		if hostname == "" {
			hostname = ep.IP
		}
		matched := MatchesManifest(hostname, manifestEndpoints)
		if matched != nil {
			report.ObservedInManifest = append(report.ObservedInManifest, MatchedEndpoint{
				Observed: *ep,
				CapID:    matched.CapID,
				CapName:  matched.CapName,
				Pattern:  matched.Pattern,
			})
			manifestMatched[matched.CapID+"|"+matched.Pattern] = true
		} else {
			report.ObservedNotInManifest = append(report.ObservedNotInManifest, *ep)
		}
	}

	// Find manifest endpoints never observed.
	for _, ep := range manifestEndpoints {
		if !manifestMatched[ep.CapID+"|"+ep.Pattern] {
			report.ManifestNeverObserved = append(report.ManifestNeverObserved, ep)
		}
	}

	// Sort all sections for deterministic output.
	sort.Slice(report.ObservedInManifest, func(i, j int) bool {
		a, b := report.ObservedInManifest[i], report.ObservedInManifest[j]
		if a.Observed.Hostname != b.Observed.Hostname {
			return a.Observed.Hostname < b.Observed.Hostname
		}
		return a.Observed.Port < b.Observed.Port
	})
	sort.Slice(report.ObservedNotInManifest, func(i, j int) bool {
		a, b := report.ObservedNotInManifest[i], report.ObservedNotInManifest[j]
		ea := effectiveHost(a)
		eb := effectiveHost(b)
		if ea != eb {
			return ea < eb
		}
		return a.Port < b.Port
	})
	sort.Slice(report.ManifestNeverObserved, func(i, j int) bool {
		return strings.ToLower(report.ManifestNeverObserved[i].Pattern) <
			strings.ToLower(report.ManifestNeverObserved[j].Pattern)
	})

	report.HasDrift = len(report.ObservedNotInManifest) > 0
	return report
}

func effectiveHost(e ObservedEndpoint) string {
	if e.Hostname != "" {
		return e.Hostname
	}
	return e.IP
}
