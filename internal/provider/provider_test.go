package provider

import (
	"net/http"
	"testing"
)

func TestNormalizeGcoreAliases(t *testing.T) {
	for _, raw := range []string{"gcore", "GCore", "g-core", "gcore-cdn", "gcorelabs"} {
		if got := Normalize(raw); got != Gcore {
			t.Fatalf("Normalize(%q) = %q, want %q", raw, got, Gcore)
		}
	}
}

func TestNormalizeFastlyAliases(t *testing.T) {
	for _, raw := range []string{"fastly", "Fastly", "fastly-cdn"} {
		if got := Normalize(raw); got != Fastly {
			t.Fatalf("Normalize(%q) = %q, want %q", raw, got, Fastly)
		}
	}
}

func TestAllIncludesGcore(t *testing.T) {
	got := All()
	if len(got) != 4 {
		t.Fatalf("All() returned %d providers, want 4", len(got))
	}
	if got[2] != Gcore {
		t.Fatalf("provider[2] = %q, want %q", got[2], Gcore)
	}
	if got[3] != Fastly {
		t.Fatalf("provider[3] = %q, want %q", got[3], Fastly)
	}
}

func TestVerifyHTTPGcore(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-ID", "fr5-hw-edge-gc50")

	verified, pop := VerifyHTTP(Gcore, 200, headers, `{"addresses":["92.223.118.6/32"]}`)
	if !verified {
		t.Fatal("expected Gcore response to verify")
	}
	if pop != "FR5" {
		t.Fatalf("pop = %q, want FR5", pop)
	}
}

func TestVerifyHTTPGcoreRejectsUnexpectedBody(t *testing.T) {
	verified, _ := VerifyHTTP(Gcore, 200, nil, `{"ok":true}`)
	if verified {
		t.Fatal("expected Gcore response without addresses to be rejected")
	}
}

func TestVerifyHTTPFastly(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Served-By", "cache-chi-kigq8000068-CHI, cache-fra-etou8220151-FRA")

	verified, pop := VerifyHTTP(Fastly, 200, headers, `{"addresses":["23.235.32.0/20"]}`)
	if !verified {
		t.Fatal("expected Fastly response to verify")
	}
	if pop != "FRA" {
		t.Fatalf("pop = %q, want FRA", pop)
	}
}

func TestVerifyHTTPFastlyRejectsUnexpectedBody(t *testing.T) {
	verified, _ := VerifyHTTP(Fastly, 200, nil, `{"ok":true}`)
	if verified {
		t.Fatal("expected Fastly response without addresses to be rejected")
	}
}

func TestDiagnosticCanaryIP(t *testing.T) {
	if got := DiagnosticCanaryIP(Gcore); got != "81.28.12.12" {
		t.Fatalf("Gcore canary = %q", got)
	}
	if got := DiagnosticCanaryIP(Fastly); got != "151.101.65.241" {
		t.Fatalf("Fastly canary = %q", got)
	}
	if got := DiagnosticCanaryIP(Cloudflare); got != "" {
		t.Fatalf("Cloudflare canary = %q, want empty", got)
	}
}
