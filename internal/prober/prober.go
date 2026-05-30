package prober

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/matinsenpai/senpaiscanner/internal/provider"
	"github.com/matinsenpai/senpaiscanner/internal/result"
)

// Config holds parameters for a single probe session.
type Config struct {
	Port               int
	Provider           provider.Kind
	Mode               Mode
	Tries              int
	Timeout            time.Duration
	SNI                string // empty = rotate automatically
	SpeedBytes         int64  // optional HTTP download sample size; 0 disables it
	InsecureSkipVerify bool   // skip TLS cert verification (use for Phase 1 where Phase 2 validates properly)
	WebSocketHost      string // empty = SNI
	WebSocketPath      string // empty = /
	RequireWebSocket   bool   // require a successful WebSocket probe for HTTP health
}

// WithPort returns a copy of Config targeting another remote port.
func (c Config) WithPort(port int) Config {
	c.Port = port
	return c
}

// Mode selects the probe type.
type Mode int

const (
	ModeTCP  Mode = iota // bare TCP connect
	ModeTLS              // TLS handshake (no HTTP)
	ModeHTTP             // full HTTPS GET /cdn-cgi/trace
)

func (m Mode) String() string {
	switch m {
	case ModeTLS:
		return "tls"
	case ModeHTTP:
		return "http"
	default:
		return "tcp"
	}
}

// ParseMode parses a mode string.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(s) {
	case "tcp":
		return ModeTCP, nil
	case "tls":
		return ModeTLS, nil
	case "http", "https":
		return ModeHTTP, nil
	default:
		return ModeTCP, fmt.Errorf("unknown mode %q (want tcp|tls|http)", s)
	}
}

// Probe runs a full measurement session against ip and returns a Result.
func Probe(ctx context.Context, ip net.IP, cfg Config) *result.Result {
	r := &result.Result{
		IP:        ip,
		Port:      cfg.Port,
		Provider:  string(provider.Normalize(string(cfg.Provider))),
		ProbeMode: cfg.Mode.String(),
		Timestamp: time.Now(),
		Latencies: make([]time.Duration, cfg.Tries),
		RequireWS: cfg.RequireWebSocket,
	}
	if cfg.Mode == ModeHTTP && cfg.SpeedBytes > 0 {
		r.SpeedTested = true
	}

	for i := 0; i < cfg.Tries; i++ {
		if ctx.Err() != nil {
			break
		}
		sni := cfg.SNI
		if sni == "" && cfg.Mode == ModeHTTP {
			sni = provider.DefaultHTTPHost(cfg.Provider)
		} else if sni == "" {
			hosts := provider.RotationHosts(cfg.Provider)
			if len(hosts) > 0 {
				sni = hosts[rand.Intn(len(hosts))]
			}
		}

		var lat time.Duration
		var tlsOk bool
		var httpStatus int
		var verified bool
		var colo string
		var throughput float64

		switch cfg.Mode {
		case ModeTCP:
			lat = probeTCP(ctx, ip, cfg.Port, cfg.Timeout)
		case ModeTLS:
			lat, tlsOk = probeTLS(ctx, ip, cfg.Port, sni, cfg.Timeout, cfg.InsecureSkipVerify)
		case ModeHTTP:
			var wsOk bool
			lat, tlsOk, httpStatus, verified, colo, throughput, wsOk = probeHTTP(
				ctx, ip, cfg.Provider, cfg.Port, sni, cfg.Timeout, cfg.SpeedBytes,
				cfg.InsecureSkipVerify, cfg.WebSocketHost, cfg.WebSocketPath, cfg.RequireWebSocket,
			)
			if wsOk {
				r.WSOk = true
			}
		}

		r.Latencies[i] = lat
		if tlsOk {
			r.TLSOk = true
		}
		if httpStatus != 0 {
			r.HTTPStatus = httpStatus
		}
		if verified {
			r.VerifiedHTTP = true
		}
		if colo != "" {
			r.Colo = colo
		}
		if throughput > 0 {
			r.Throughput = throughput
		}

		// Small jitter between tries to avoid looking like a scanner
		if i < cfg.Tries-1 {
			jitter := time.Duration(rand.Intn(50)+10) * time.Millisecond
			select {
			case <-ctx.Done():
			case <-time.After(jitter):
			}
		}
	}

	return r
}

// probeTCP measures a raw TCP connect time.
func probeTCP(ctx context.Context, ip net.IP, port int, timeout time.Duration) time.Duration {
	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	dl := time.Now().Add(timeout)
	dialCtx, cancel := context.WithDeadline(ctx, dl)
	defer cancel()

	d := net.Dialer{}
	start := time.Now()
	conn, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return 0
	}
	lat := time.Since(start)
	conn.Close()
	return lat
}

// probeTLS measures a TLS handshake time.
func probeTLS(ctx context.Context, ip net.IP, port int, sni string, timeout time.Duration, insecure bool) (time.Duration, bool) {
	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	dl := time.Now().Add(timeout)
	dialCtx, cancel := context.WithDeadline(ctx, dl)
	defer cancel()

	d := tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: insecure,
			MinVersion:         tls.VersionTLS12,
		},
	}

	start := time.Now()
	conn, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return 0, false
	}
	lat := time.Since(start)
	conn.Close()
	return lat, true
}

// probeHTTP validates the candidate IP using a provider-specific HTTP request.
func probeHTTP(ctx context.Context, ip net.IP, kind provider.Kind, port int, sni string, timeout time.Duration, speedBytes int64, insecure bool, wsHost, wsPath string, requireWS bool) (
	lat time.Duration, tlsOk bool, httpStatus int, verified bool, colo string, throughput float64, wsOk bool,
) {
	addr := fmt.Sprintf("%s:%d", ip.String(), port)

	// Budget split: TCP gets ¼, TLS gets ½, leaving ¼ guaranteed for the HTTP
	// GET+response. Without this, on DPI-throttled networks the TLS handshake
	// can silently consume the entire http.Client.Timeout, making the HTTP
	// phase impossible and producing false-positive packet loss.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: timeout / 4}).DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         sni,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: insecure,
		},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: timeout / 2,
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	scheme := "https"
	if port == 80 {
		scheme = "http"
	}
	url := fmt.Sprintf("%s://%s%s", scheme, sni, provider.DefaultHTTPPath(kind))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "senpaiscanner/1.0")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, false, 0, false, "", 0, false
	}
	lat = time.Since(start)
	defer resp.Body.Close()

	tlsOk = resp.TLS != nil
	httpStatus = resp.StatusCode
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	verified, colo = provider.VerifyHTTP(kind, httpStatus, resp.Header, string(body))
	if speedBytes > 0 && verified && provider.SupportsDownload(kind) {
		throughput = probeDownload(ctx, ip, kind, port, timeout, speedBytes)
	}

	if verified && provider.SupportsWebSocketHold(kind) && (speedBytes > 0 || requireWS) {
		wsOk = probeWebSocket(ctx, ip, port, sni, wsHost, wsPath, timeout)
	}

	return
}

// probeWebSocket tests whether WebSocket-grade TLS connections reach the
// provider edge without being killed by DPI.
func probeWebSocket(ctx context.Context, ip net.IP, port int, sni, host, path string, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	if host == "" {
		host = sni
	}
	path = normalizeWSPath(path)

	dialer := &net.Dialer{Timeout: timeout / 3}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // cert already verified in probeHTTP
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return false
	}

	// Phase 1: idle hold.
	tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
	oneByte := make([]byte, 1)
	if _, err := tlsConn.Read(oneByte); err != nil {
		if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
			return false
		}
	}

	// Phase 2: send WebSocket upgrade and verify the edge responds.
	wsReq := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Key: c2VucGFpc2Nhbm5lcg==\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"\r\n", path, host)

	tlsConn.SetDeadline(time.Now().Add(timeout / 2))
	if _, err := tlsConn.Write([]byte(wsReq)); err != nil {
		return false
	}

	buf := make([]byte, 1024)
	tlsConn.SetDeadline(time.Now().Add(timeout / 3))
	n, err := tlsConn.Read(buf)
	if err != nil || n == 0 {
		return false
	}

	return strings.Contains(string(buf[:n]), "HTTP/")
}

func normalizeWSPath(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

// probeDownload fetches a small provider-owned payload sample while forcing
// the TCP connection to the candidate IP.
func probeDownload(ctx context.Context, ip net.IP, kind provider.Kind, port int, timeout time.Duration, bytes int64) float64 {
	if bytes <= 0 {
		return 0
	}

	downloadURL := provider.DownloadURL(kind, "https", bytes)
	if downloadURL == "" {
		return 0
	}

	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: timeout / 4}).DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName: provider.DefaultHTTPHost(kind),
			MinVersion: tls.VersionTLS12,
		},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: timeout / 2,
	}
	client := &http.Client{Timeout: timeout, Transport: transport}

	scheme := "https"
	if port == 80 {
		scheme = "http"
	}
	url := provider.DownloadURL(kind, scheme, bytes)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", "senpaiscanner/1.0")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return 0
	}

	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, bytes))
	if err != nil || n <= 0 {
		return 0
	}
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return float64(n) / elapsed
}
