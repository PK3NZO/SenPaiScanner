package result

import (
	"math"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/matinsenpai/senpaiscanner/internal/provider"
)

// Result holds all measured statistics for a single Cloudflare IP.
type Result struct {
	IP           net.IP
	Port         int
	Provider     string
	ProbeMode    string          // tcp | tls | http
	Latencies    []time.Duration // per-try latencies; 0 = failed try
	TLSOk        bool
	WSOk         bool // WebSocket connection survived hold test
	RequireWS    bool // true when WebSocket success is part of health criteria
	HTTPStatus   int
	VerifiedHTTP bool
	Colo         string
	Throughput   float64 // bytes/sec, 0 if not measured
	SpeedTested  bool    // true when a payload download check was attempted
	Timestamp    time.Time
}

// Loss returns packet loss percentage (0–100).
func (r *Result) Loss() float64 {
	if len(r.Latencies) == 0 {
		return 100
	}
	failed := 0
	for _, l := range r.Latencies {
		if l == 0 {
			failed++
		}
	}
	return float64(failed) / float64(len(r.Latencies)) * 100
}

// Avg returns the mean of successful latency measurements.
func (r *Result) Avg() time.Duration {
	var sum time.Duration
	var count int
	for _, l := range r.Latencies {
		if l > 0 {
			sum += l
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return sum / time.Duration(count)
}

// Min returns the best successful latency.
func (r *Result) Min() time.Duration {
	var m time.Duration
	for _, l := range r.Latencies {
		if l > 0 && (m == 0 || l < m) {
			m = l
		}
	}
	return m
}

// Max returns the worst successful latency.
func (r *Result) Max() time.Duration {
	var m time.Duration
	for _, l := range r.Latencies {
		if l > m {
			m = l
		}
	}
	return m
}

// Jitter returns the standard deviation of successful latencies.
func (r *Result) Jitter() time.Duration {
	var count int
	for _, l := range r.Latencies {
		if l > 0 {
			count++
		}
	}
	if count < 2 {
		return 0
	}
	avg := float64(r.Avg())
	var variance float64
	for _, l := range r.Latencies {
		if l > 0 {
			diff := float64(l) - avg
			variance += diff * diff
		}
	}
	variance /= float64(count)
	return time.Duration(math.Sqrt(variance))
}

// IsHealthy returns true only when the probe mode's success criteria are met.
// A failed try must record latency 0; timeouts must never count as success.
func (r *Result) IsHealthy() bool {
	if r.Loss() >= 50 || r.Avg() <= 0 {
		return false
	}

	switch r.ProbeMode {
	case "http":
		// Plain HTTP (port 80) has no TLS; every other HTTP-mode port is HTTPS.
		if r.Port != 80 && !r.TLSOk {
			return false
		}
		if !r.VerifiedHTTP {
			return false
		}
		if r.SpeedTested && r.Throughput <= 0 {
			return false
		}
		if r.RequireWS && !r.WSOk {
			return false
		}
		kind := provider.Normalize(strings.ToLower(r.Provider))
		if kind == provider.Cloudflare && r.Colo == "" {
			return false
		}
		return true
	case "tls":
		return r.TLSOk
	default: // tcp
		return true
	}
}

// SortBy defines the available sort criteria.
type SortBy int

const (
	SortByAvg SortBy = iota
	SortByLoss
	SortByJitter
	SortByColo
	SortBySpeed
)

// Sort reorders results in-place according to the given criterion (ascending).
func Sort(results []*Result, by SortBy) {
	sort.Slice(results, func(i, j int) bool {
		a, b := results[i], results[j]
		switch by {
		case SortByLoss:
			if a.Loss() != b.Loss() {
				return a.Loss() < b.Loss()
			}
			return a.Avg() < b.Avg()
		case SortByJitter:
			return a.Jitter() < b.Jitter()
		case SortByColo:
			if a.Colo != b.Colo {
				return a.Colo < b.Colo
			}
			return a.Avg() < b.Avg()
		case SortBySpeed:
			if a.Throughput != b.Throughput {
				return a.Throughput > b.Throughput
			}
			return a.Avg() < b.Avg()
		default: // SortByAvg
			if a.Avg() != b.Avg() {
				if a.Avg() == 0 {
					return false
				}
				if b.Avg() == 0 {
					return true
				}
				return a.Avg() < b.Avg()
			}
			return a.Loss() < b.Loss()
		}
	})
}

// TopN returns the n best results by Avg latency (ignoring unhealthy IPs).
func TopN(results []*Result, n int) []*Result {
	var healthy []*Result
	for _, r := range results {
		if r.IsHealthy() {
			healthy = append(healthy, r)
		}
	}
	Sort(healthy, SortByAvg)
	if n > 0 && n < len(healthy) {
		return healthy[:n]
	}
	return healthy
}
