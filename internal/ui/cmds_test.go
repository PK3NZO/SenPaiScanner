package ui

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matinsenpai/senpaiscanner/internal/prober"
	"github.com/matinsenpai/senpaiscanner/internal/provider"
	"github.com/matinsenpai/senpaiscanner/internal/result"
)

func TestConfigProbeFromURLUsesConfigPortSNIAndWebSocket(t *testing.T) {
	raw := "vless://3441b906-471f-4160-8f2c-a981793e6155@104.17.89.5:2087?encryption=none&security=tls&sni=winter-thunder-0638.matinsenpaivideo2.workers.dev&fp=chrome&insecure=0&allowInsecure=0&type=ws&host=winter-thunder-0638.matinsenpaivideo2.workers.dev&path=%2F#CF"

	cfg, err := configProbeFromURL(raw, 7*time.Second, provider.Cloudflare)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Port != 2087 {
		t.Fatalf("port = %d, want 2087", cfg.Port)
	}
	if cfg.SNI != "winter-thunder-0638.matinsenpaivideo2.workers.dev" {
		t.Fatalf("SNI = %q", cfg.SNI)
	}
	if cfg.WebSocketHost != "winter-thunder-0638.matinsenpaivideo2.workers.dev" {
		t.Fatalf("WebSocketHost = %q", cfg.WebSocketHost)
	}
	if cfg.WebSocketPath != "/" {
		t.Fatalf("WebSocketPath = %q, want /", cfg.WebSocketPath)
	}
	if !cfg.RequireWebSocket {
		t.Fatal("RequireWebSocket = false, want true")
	}
}

func TestConfigProbeFromURLUsesCloudFrontTLSShortlist(t *testing.T) {
	raw := "vless://3441b906-471f-4160-8f2c-a981793e6155@1.2.3.4:443?encryption=none&security=tls&sni=d111111abcdef8.cloudfront.net&type=ws&host=example.com&path=%2Fws#CFD"

	cfg, err := configProbeFromURL(raw, 7*time.Second, provider.CloudFront)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Provider != provider.CloudFront {
		t.Fatalf("Provider = %q, want %q", cfg.Provider, provider.CloudFront)
	}
	if cfg.Mode != prober.ModeTLS {
		t.Fatalf("Mode = %s, want tls", cfg.Mode)
	}
	if cfg.SNI != "d111111abcdef8.cloudfront.net" {
		t.Fatalf("SNI = %q, want config SNI", cfg.SNI)
	}
	if cfg.Port != 443 {
		t.Fatalf("Port = %d, want 443", cfg.Port)
	}
	if cfg.Tries != 1 {
		t.Fatalf("Tries = %d, want 1 for shared CDN config shortlist", cfg.Tries)
	}
	if !cfg.EarlyStop {
		t.Fatal("EarlyStop = false, want true")
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify = false, want true for Phase 1 shortlist")
	}
	if cfg.RequireWebSocket {
		t.Fatal("RequireWebSocket = true, want false for CloudFront")
	}
}

func TestDefaultPhase1ProbeConfigKeepsCloudFrontHTTPValidation(t *testing.T) {
	cfg := defaultPhase1ProbeConfig(7*time.Second, provider.CloudFront)
	if cfg.Provider != provider.CloudFront {
		t.Fatalf("Provider = %q, want %q", cfg.Provider, provider.CloudFront)
	}
	if cfg.Mode != prober.ModeHTTP {
		t.Fatalf("Mode = %s, want http", cfg.Mode)
	}
	if cfg.SNI != provider.DefaultHTTPHost(provider.CloudFront) {
		t.Fatalf("SNI = %q, want default CloudFront host", cfg.SNI)
	}
	if !cfg.EarlyStop {
		t.Fatal("EarlyStop = false, want true")
	}
}

func TestConfigProbeFromURLUsesGcoreTLSShortlist(t *testing.T) {
	raw := "vless://3441b906-471f-4160-8f2c-a981793e6155@1.2.3.4:8443?encryption=none&security=tls&sni=customer.example&type=ws&host=customer.example&path=%2Fws#Gcore"

	cfg, err := configProbeFromURL(raw, 7*time.Second, provider.Gcore)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Provider != provider.Gcore {
		t.Fatalf("Provider = %q, want %q", cfg.Provider, provider.Gcore)
	}
	if cfg.Mode != prober.ModeTLS {
		t.Fatalf("Mode = %s, want tls", cfg.Mode)
	}
	if cfg.SNI != "customer.example" {
		t.Fatalf("SNI = %q, want config SNI", cfg.SNI)
	}
	if cfg.Port != 8443 {
		t.Fatalf("Port = %d, want 8443", cfg.Port)
	}
	if cfg.Tries != 1 {
		t.Fatalf("Tries = %d, want 1 for shared CDN config shortlist", cfg.Tries)
	}
	if !cfg.EarlyStop {
		t.Fatal("EarlyStop = false, want true")
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify = false, want true for Phase 1 shortlist")
	}
	if cfg.RequireWebSocket {
		t.Fatal("RequireWebSocket = true, want false for Gcore")
	}
}

func TestDefaultPhase1ProbeConfigKeepsGcoreHTTPValidation(t *testing.T) {
	cfg := defaultPhase1ProbeConfig(7*time.Second, provider.Gcore)
	if cfg.Provider != provider.Gcore {
		t.Fatalf("Provider = %q, want %q", cfg.Provider, provider.Gcore)
	}
	if cfg.Mode != prober.ModeHTTP {
		t.Fatalf("Mode = %s, want http", cfg.Mode)
	}
	if cfg.SNI != provider.DefaultHTTPHost(provider.Gcore) {
		t.Fatalf("SNI = %q, want default Gcore host", cfg.SNI)
	}
	if !cfg.EarlyStop {
		t.Fatal("EarlyStop = false, want true")
	}
}

func TestConfigProbeFromURLUsesFastlyTLSShortlist(t *testing.T) {
	raw := "vless://3441b906-471f-4160-8f2c-a981793e6155@1.2.3.4:8443?encryption=none&security=tls&sni=customer.example&type=ws&host=customer.example&path=%2Fws#Fastly"

	cfg, err := configProbeFromURL(raw, 7*time.Second, provider.Fastly)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Provider != provider.Fastly {
		t.Fatalf("Provider = %q, want %q", cfg.Provider, provider.Fastly)
	}
	if cfg.Mode != prober.ModeTLS {
		t.Fatalf("Mode = %s, want tls", cfg.Mode)
	}
	if cfg.SNI != "customer.example" {
		t.Fatalf("SNI = %q, want config SNI", cfg.SNI)
	}
	if cfg.Port != 8443 {
		t.Fatalf("Port = %d, want 8443", cfg.Port)
	}
	if cfg.Tries != 1 {
		t.Fatalf("Tries = %d, want 1 for shared CDN config shortlist", cfg.Tries)
	}
	if !cfg.EarlyStop {
		t.Fatal("EarlyStop = false, want true")
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify = false, want true for Phase 1 shortlist")
	}
	if cfg.RequireWebSocket {
		t.Fatal("RequireWebSocket = true, want false for Fastly")
	}
}

func TestDefaultPhase1ProbeConfigKeepsFastlyHTTPValidation(t *testing.T) {
	cfg := defaultPhase1ProbeConfig(7*time.Second, provider.Fastly)
	if cfg.Provider != provider.Fastly {
		t.Fatalf("Provider = %q, want %q", cfg.Provider, provider.Fastly)
	}
	if cfg.Mode != prober.ModeTLS {
		t.Fatalf("Mode = %s, want tls", cfg.Mode)
	}
	if cfg.SNI != provider.DefaultHTTPHost(provider.Fastly) {
		t.Fatalf("SNI = %q, want default Fastly host", cfg.SNI)
	}
	if cfg.SpeedBytes != 0 {
		t.Fatalf("SpeedBytes = %d, want 0 for TLS mode", cfg.SpeedBytes)
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify = false, want true for Fastly TLS shortlist")
	}
	if !cfg.EarlyStop {
		t.Fatal("EarlyStop = false, want true")
	}
}

func TestPrependProviderCanaryAddsFastlyCanaryFirst(t *testing.T) {
	input := make(chan net.IP, 2)
	input <- net.ParseIP("151.101.1.1")
	input <- net.ParseIP("151.101.2.1")
	close(input)

	var got []string
	for ip := range prependProviderCanary(context.Background(), provider.Fastly, input) {
		got = append(got, ip.String())
	}
	if len(got) != 3 {
		t.Fatalf("got %d IPs, want 3", len(got))
	}
	if got[0] != provider.DiagnosticCanaryIP(provider.Fastly) {
		t.Fatalf("first IP = %s, want Fastly canary", got[0])
	}
}

func TestPrependProviderCanarySkipsDuplicate(t *testing.T) {
	input := make(chan net.IP, 2)
	input <- net.ParseIP(provider.DiagnosticCanaryIP(provider.Fastly))
	input <- net.ParseIP("151.101.2.1")
	close(input)

	var got []string
	for ip := range prependProviderCanary(context.Background(), provider.Fastly, input) {
		got = append(got, ip.String())
	}
	if len(got) != 2 {
		t.Fatalf("got %d IPs, want 2", len(got))
	}
	if got[0] != provider.DiagnosticCanaryIP(provider.Fastly) {
		t.Fatalf("first IP = %s, want Fastly canary", got[0])
	}
}

func TestRunConfigPortProbesCapsNeighborExpansion(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})

	port := ln.Addr().(*net.TCPAddr).Port
	ips := make(chan net.IP, 1)
	ips <- net.ParseIP("127.0.0.1")
	close(ips)
	_, loopbackNet, err := net.ParseCIDR("127.0.0.0/30")
	if err != nil {
		t.Fatal(err)
	}

	var callbacks int64
	runConfigPortProbes(
		context.Background(),
		ips,
		[]int{port},
		4,
		prober.Config{
			Port:     port,
			Provider: provider.Cloudflare,
			Mode:     prober.ModeTCP,
			Tries:    1,
			Timeout:  100 * time.Millisecond,
		},
		func(_ *result.Result) {
			atomic.AddInt64(&callbacks, 1)
		},
		neighborScanOpts{
			enabled:  true,
			nets:     []*net.IPNet{loopbackNet},
			radius:   2,
			perHit:   2,
			maxTotal: 2,
		},
		1,
	)

	if got := atomic.LoadInt64(&callbacks); got != 1 {
		t.Fatalf("callbacks = %d, want 1", got)
	}
}

func TestRunConfigPortProbesDoesNotDeadlockWhenNeighborQueueIsFull(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	doneAccept := make(chan struct{})
	go func() {
		defer close(doneAccept)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-doneAccept
	})

	port := ln.Addr().(*net.TCPAddr).Port
	ips := make(chan net.IP, 1)
	ips <- net.ParseIP("127.0.0.1")
	close(ips)
	_, loopbackNet, err := net.ParseCIDR("127.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		runConfigPortProbes(
			context.Background(),
			ips,
			[]int{port},
			1,
			prober.Config{
				Port:     port,
				Provider: provider.Cloudflare,
				Mode:     prober.ModeTCP,
				Tries:    1,
				Timeout:  100 * time.Millisecond,
			},
			func(_ *result.Result) {},
			neighborScanOpts{
				enabled:  true,
				nets:     []*net.IPNet{loopbackNet},
				radius:   60,
				perHit:   60,
				maxTotal: 60,
			},
			20,
		)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runConfigPortProbes deadlocked while enqueueing neighbors")
	}
}
