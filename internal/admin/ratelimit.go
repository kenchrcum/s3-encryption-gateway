package admin

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// RateLimiter implements a simple token-bucket rate limiter per source IP
// for the admin listener. Admin endpoints are low-QPS, so a simple
// implementation suffices.
type RateLimiter struct {
	mu          sync.Mutex
	buckets     map[string]*bucket
	rpm         int     // requests per minute
	globalRPM   int     // global cap across all IPs
	globalCount int
	globalReset time.Time
	logger      *logrus.Logger
}

type bucket struct {
	tokens    float64
	lastCheck time.Time
}

const maxAdminRateLimitClients = 10_000

// NewRateLimiter creates a new per-IP rate limiter.
func NewRateLimiter(requestsPerMinute int, logger *logrus.Logger) *RateLimiter {
	return &RateLimiter{
		buckets:   make(map[string]*bucket),
		rpm:       requestsPerMinute,
		globalRPM: 120, // global cap of 120 rpm at the listener
		logger:    logger,
	}
}

// Middleware returns HTTP middleware that enforces rate limiting.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		if !rl.allow(ip) {
			writeAdminError(w, http.StatusTooManyRequests, "TooManyRequests", "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Map-size cap to prevent memory exhaustion under IP-churn DDoS.
	if _, exists := rl.buckets[ip]; !exists && len(rl.buckets) >= maxAdminRateLimitClients {
		return false
	}

	// Check global rate limit
	if now.After(rl.globalReset) {
		rl.globalCount = 0
		rl.globalReset = now.Add(time.Minute)
	}
	if rl.globalCount >= rl.globalRPM {
		return false
	}

	// Check per-IP rate limit
	b, ok := rl.buckets[ip]
	if !ok {
		b = &bucket{
			tokens:    float64(rl.rpm),
			lastCheck: now,
		}
		rl.buckets[ip] = b
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastCheck).Seconds()
	b.tokens += elapsed * float64(rl.rpm) / 60.0
	if b.tokens > float64(rl.rpm) {
		b.tokens = float64(rl.rpm)
	}
	b.lastCheck = now

	if b.tokens < 1.0 {
		return false
	}

	b.tokens--
	rl.globalCount++

	// Periodic cleanup of stale buckets (every 100th request)
	if rl.globalCount%100 == 0 {
		rl.cleanup(now)
	}

	return true
}

func (rl *RateLimiter) cleanup(now time.Time) {
	staleThreshold := now.Add(-5 * time.Minute)
	for ip, b := range rl.buckets {
		if b.lastCheck.Before(staleThreshold) {
			delete(rl.buckets, ip)
		}
	}
}

func extractIP(r *http.Request) string {
	// Do NOT trust X-Forwarded-For — the admin listener should be accessed
	// directly, not through a load balancer. Defense in depth per BSRS Ch. 5.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
