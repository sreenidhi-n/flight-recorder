package server

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// rateLimiter is a simple token-bucket rate limiter per IP address.
// It limits requests to maxReqs per window. Not distributed — per-process only.
// Good enough for v3.0 (single Fly.io instance). Upgrade to Redis for multi-instance.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	max     int
	window  time.Duration
}

type bucket struct {
	count    int
	resetAt  time.Time
}

func newRateLimiter(maxReqs int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		buckets: make(map[string]*bucket),
		max:     maxReqs,
		window:  window,
	}
	// Periodically clean up expired buckets.
	go func() {
		for range time.Tick(5 * time.Minute) {
			rl.cleanup()
		}
	}()
	return rl
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[ip]
	if !ok || now.After(b.resetAt) {
		rl.buckets[ip] = &bucket{count: 1, resetAt: now.Add(rl.window)}
		return true
	}
	if b.count >= rl.max {
		return false
	}
	b.count++
	return true
}

func (rl *rateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	for ip, b := range rl.buckets {
		if now.After(b.resetAt) {
			delete(rl.buckets, ip)
		}
	}
}

// RateLimitMiddleware wraps a handler to limit requests per IP.
// Responds 429 Too Many Requests when the limit is exceeded.
func RateLimitMiddleware(maxReqs int, window time.Duration, next http.Handler) http.Handler {
	rl := newRateLimiter(maxReqs, window)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !rl.allow(ip) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP extracts the real client IP, respecting Fly.io / proxy forwarding.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// First IP in the chain is the client.
		if idx := len(xff); idx > 0 {
			if ip, _, err := net.SplitHostPort(xff); err == nil {
				return ip
			}
			// No port — take as-is up to first comma.
			for i, c := range xff {
				if c == ',' {
					return xff[:i]
				}
			}
			return xff
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
