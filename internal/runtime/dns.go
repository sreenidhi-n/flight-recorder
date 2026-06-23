package runtime

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// Resolver maps IP addresses to hostnames.
// Implementations must be safe for concurrent use.
type Resolver interface {
	Lookup(ip string) string
}

// DNSResolver resolves IPs to hostnames via reverse DNS with an in-memory cache.
// Cache entries never expire within a single CLI invocation — the lifetime of
// the resolver matches the lifetime of the command.
type DNSResolver struct {
	timeout time.Duration
	mu      sync.Mutex
	cache   map[string]string
}

// NewDNSResolver creates a resolver with the given per-lookup timeout.
func NewDNSResolver(timeout time.Duration) *DNSResolver {
	return &DNSResolver{
		timeout: timeout,
		cache:   make(map[string]string),
	}
}

// Lookup returns the first hostname for ip, or "" if resolution fails or times out.
// Results are cached for the lifetime of the resolver.
func (r *DNSResolver) Lookup(ip string) string {
	r.mu.Lock()
	if h, ok := r.cache[ip]; ok {
		r.mu.Unlock()
		return h
	}
	r.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupAddr(ctx, ip)
	hostname := ""
	if err == nil && len(addrs) > 0 {
		// LookupAddr returns FQDNs with trailing dot — strip it.
		hostname = strings.TrimSuffix(addrs[0], ".")
	}

	r.mu.Lock()
	r.cache[ip] = hostname
	r.mu.Unlock()
	return hostname
}

// MapResolver is a static resolver backed by a pre-populated map.
// Used in tests to avoid real DNS lookups.
type MapResolver struct {
	m map[string]string
}

// NewMapResolver wraps a map for deterministic test lookups.
func NewMapResolver(m map[string]string) *MapResolver {
	return &MapResolver{m: m}
}

func (r *MapResolver) Lookup(ip string) string {
	return r.m[ip]
}
