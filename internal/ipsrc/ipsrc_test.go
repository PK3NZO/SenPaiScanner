package ipsrc

import (
	"context"
	"math/rand"
	"net"
	"testing"

	"github.com/matinsenpai/senpaiscanner/internal/provider"
)

func TestNewV4Only(t *testing.T) {
	s, err := New(true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.v4Nets) == 0 {
		t.Error("expected v4 nets to be loaded")
	}
	if len(s.v6Nets) != 0 {
		t.Error("expected no v6 nets when useV6=false")
	}
}

func TestNewV6Only(t *testing.T) {
	s, err := New(false, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.v6Nets) == 0 {
		t.Error("expected v6 nets to be loaded")
	}
}

func TestNewExtraCIDR(t *testing.T) {
	s, err := New(false, false, []string{"1.1.1.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.v4Nets) == 0 {
		t.Error("extra v4 CIDR not loaded")
	}
}

func TestNewNoRanges(t *testing.T) {
	_, err := New(false, false, nil)
	if err == nil {
		t.Error("expected error with no ranges")
	}
}

func TestRandom(t *testing.T) {
	s, err := New(true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		ip := s.Random()
		if ip == nil {
			t.Fatal("Random() returned nil")
		}
		if ip.To4() == nil {
			t.Errorf("expected IPv4, got %s", ip)
		}
	}
}

func TestRandomIsInCFRange(t *testing.T) {
	s, err := New(true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		ip := s.Random()
		inRange := false
		for _, n := range s.v4Nets {
			if n.Contains(ip) {
				inRange = true
				break
			}
		}
		if !inRange {
			t.Errorf("random IP %s not in any Cloudflare range", ip)
		}
	}
}

func TestRandomWeightsRangesByAddressCount(t *testing.T) {
	_, large, err := net.ParseCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, small, err := net.ParseCIDR("192.0.2.0/30")
	if err != nil {
		t.Fatal(err)
	}
	s := &Source{
		v4Nets: []*net.IPNet{large, small},
		rng:    rand.New(rand.NewSource(1)),
	}

	smallHits := 0
	for i := 0; i < 200; i++ {
		if small.Contains(s.Random()) {
			smallHits++
		}
	}
	if smallHits > 20 {
		t.Fatalf("small /30 range got %d/200 hits; random picker is not weighted by CIDR size", smallHits)
	}
}

func TestStream(t *testing.T) {
	s, err := New(true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ch := s.Stream(ctx, 10)
	count := 0
	for range ch {
		count++
	}
	if count != 10 {
		t.Errorf("Stream(10) emitted %d IPs, want 10", count)
	}
}

func TestStreamCancel(t *testing.T) {
	s, err := New(true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ch := s.Stream(ctx, 0)
	cancel()
	count := 0
	for range ch {
		count++
	}
	// Some IPs may have been buffered before cancel; just ensure it terminates
}

func TestFromCIDR(t *testing.T) {
	ctx := context.Background()
	ch, err := FromCIDR(ctx, "192.0.2.0/30")
	if err != nil {
		t.Fatal(err)
	}
	var ips []net.IP
	for ip := range ch {
		ips = append(ips, ip)
	}
	if len(ips) != 4 {
		t.Errorf("expected 4 IPs from /30, got %d", len(ips))
	}
}

func TestInvalidCIDR(t *testing.T) {
	_, err := New(false, false, []string{"not-a-cidr"})
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestNewWithOptionsCIDROnly(t *testing.T) {
	s, err := NewWithOptions(true, true, []string{"192.0.2.0/30"}, Options{UseBuiltin: false})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.v4Nets) != 1 {
		t.Fatalf("expected exactly one v4 CIDR, got %d", len(s.v4Nets))
	}
	if got := s.v4Nets[0].String(); got != "192.0.2.0/30" {
		t.Fatalf("expected custom CIDR only, got %s", got)
	}
	if len(s.v6Nets) != 0 {
		t.Fatalf("expected no v6 CIDRs, got %d", len(s.v6Nets))
	}
}

func TestNewWithCloudFrontBuiltins(t *testing.T) {
	s, err := NewWithOptions(true, false, nil, Options{UseBuiltin: true, Provider: provider.CloudFront})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.v4Nets) == 0 {
		t.Fatal("expected CloudFront IPv4 ranges to load")
	}
	if len(s.v6Nets) != 0 {
		t.Fatalf("expected no CloudFront IPv6 ranges, got %d", len(s.v6Nets))
	}
}

func TestNewWithGcoreBuiltins(t *testing.T) {
	s, err := NewWithOptions(true, false, nil, Options{UseBuiltin: true, Provider: provider.Gcore})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.v4Nets) != 978 {
		t.Fatalf("expected 978 Gcore IPv4 ranges, got %d", len(s.v4Nets))
	}
	if len(s.v6Nets) != 0 {
		t.Fatalf("expected no Gcore IPv6 ranges, got %d", len(s.v6Nets))
	}
	if got := s.v4Nets[0].String(); got != "101.53.220.210/32" {
		t.Fatalf("first Gcore range = %s", got)
	}
}

func TestGcoreStreamStopsAtFiniteCapacity(t *testing.T) {
	s, err := NewWithOptions(true, false, nil, Options{UseBuiltin: true, Provider: provider.Gcore})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.CountUpTo(1000); got != 978 {
		t.Fatalf("CountUpTo(1000) = %d, want 978", got)
	}

	ctx := context.Background()
	got := 0
	for range s.Stream(ctx, 1000) {
		got++
	}
	if got != 978 {
		t.Fatalf("Stream(1000) emitted %d IPs, want 978", got)
	}
}

func TestNewWithFastlyBuiltins(t *testing.T) {
	s, err := NewWithOptions(true, false, nil, Options{UseBuiltin: true, Provider: provider.Fastly})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.v4Nets) != 19 {
		t.Fatalf("expected 19 Fastly IPv4 ranges, got %d", len(s.v4Nets))
	}
	if len(s.v6Nets) != 0 {
		t.Fatalf("expected no Fastly IPv6 ranges, got %d", len(s.v6Nets))
	}
	if got := s.v4Nets[0].String(); got != "23.235.32.0/20" {
		t.Fatalf("first Fastly range = %s", got)
	}
	if got := s.CountUpTo(1000); got != 1000 {
		t.Fatalf("CountUpTo(1000) = %d, want 1000", got)
	}
}

func TestFastlyRandomIsInFastlyRange(t *testing.T) {
	s, err := NewWithOptions(true, false, nil, Options{UseBuiltin: true, Provider: provider.Fastly})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		ip := s.Random()
		inRange := false
		for _, n := range s.v4Nets {
			if n.Contains(ip) {
				inRange = true
				break
			}
		}
		if !inRange {
			t.Fatalf("random IP %s not in any Fastly range", ip)
		}
	}
}

func TestFastlyStreamCanEmit200KUniqueIPs(t *testing.T) {
	s, err := NewWithOptions(true, false, nil, Options{UseBuiltin: true, Provider: provider.Fastly})
	if err != nil {
		t.Fatal(err)
	}
	const want = 200000
	if got := s.CountUpTo(want); got != want {
		t.Fatalf("CountUpTo(%d) = %d, want %d", want, got, want)
	}

	seen := make(map[string]struct{}, want)
	for ip := range s.Stream(context.Background(), want) {
		key := ip.String()
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate IP emitted: %s", key)
		}
		inRange := false
		for _, n := range s.v4Nets {
			if n.Contains(ip) {
				inRange = true
				break
			}
		}
		if !inRange {
			t.Fatalf("streamed IP %s not in any Fastly range", ip)
		}
		seen[key] = struct{}{}
	}
	if len(seen) != want {
		t.Fatalf("Stream(%d) emitted %d IPs, want %d", want, len(seen), want)
	}
}
