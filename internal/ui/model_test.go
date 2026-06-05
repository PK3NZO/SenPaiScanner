package ui

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/matinsenpai/senpaiscanner/internal/provider"
	"github.com/matinsenpai/senpaiscanner/internal/result"
	"github.com/matinsenpai/senpaiscanner/internal/xraytest"
)

func TestMenuOnlyShowsMainWorkflow(t *testing.T) {
	if len(menuEntries) != 4 {
		t.Fatalf("menu entries = %d, want 4", len(menuEntries))
	}
	if menuEntries[0].label != "Find Working IPs" {
		t.Fatalf("first menu item = %q, want Find Working IPs", menuEntries[0].label)
	}
	for _, entry := range menuEntries {
		for _, removed := range []string{"Quick Scan", "Custom Scan", "Test IPs", "Discover Colos"} {
			if entry.label == removed {
				t.Fatalf("removed menu item %q is still visible", removed)
			}
		}
	}
}

func TestRenderedMenuMatchesMainWorkflow(t *testing.T) {
	m := NewApp("test")
	entries := m.menuEntries()
	if len(entries) != 4 {
		t.Fatalf("rendered menu entries = %d, want 4", len(entries))
	}
	for _, entry := range entries {
		for _, removed := range []string{"Quick Scan", "Custom Scan", "Scan with Config", "Test IPs", "Discover Colos"} {
			if entry.label == removed {
				t.Fatalf("removed menu item %q is still rendered", removed)
			}
		}
	}
}

func TestFindWorkingIPsMenuOpensUnifiedConfigFlow(t *testing.T) {
	m := NewApp("test")
	m.menuIdx = menuFindWorking

	next, cmd := m.selectMenuItem()
	if cmd != nil {
		t.Fatal("selectMenuItem returned unexpected command")
	}
	got := next.(AppModel)
	if got.page != PageScanWithConfig {
		t.Fatalf("page = %v, want PageScanWithConfig", got.page)
	}
	if got.configSetupRow != 0 || got.configOptionalRow != 0 {
		t.Fatalf("config rows = (%d,%d), want (0,0)", got.configSetupRow, got.configOptionalRow)
	}
}

func TestConfigPhase1ViewStaysWithinTerminalHeight(t *testing.T) {
	m := NewApp("test")
	m.page = PageConfigPhase1
	m.width = 120
	m.height = 30
	m.configURL = "vless://redacted"
	m.liveResultPath = "/Users/pouriarc/Projects/SenPaiScanner/SenPaiScannerResult-20260530-193925.txt"
	for i := 0; i < 30; i++ {
		m.configPhase1Results = append(m.configPhase1Results, &result.Result{
			IP:           net.ParseIP(fmt.Sprintf("23.228.222.%d", i+1)),
			Port:         443,
			Provider:     "cloudfront",
			ProbeMode:    "tls",
			Latencies:    []time.Duration{150 * time.Millisecond},
			TLSOk:        true,
			VerifiedHTTP: true,
		})
	}

	view := m.viewConfigPhase1()
	lines := strings.Split(strings.TrimSuffix(view, "\n"), "\n")
	if len(lines) > m.height {
		t.Fatalf("view lines = %d, want <= %d\n%s", len(lines), m.height, view)
	}
	if strings.Contains(view, "/Users/pouriarc/Projects") {
		t.Fatalf("view should render compact live path:\n%s", view)
	}
}

func TestResolvePhase1OptionsUsesRandomCloudflareDefaults(t *testing.T) {
	m := NewApp("test")
	m.configURL = "vless://12345678-1234-1234-1234-123456789abc@example.com:443?encryption=none&security=tls&type=ws&host=example.com&path=%2F#test"
	m.configCountIdx = 1

	opts := m.resolvePhase1Options()
	if opts.count != 5000 {
		t.Fatalf("count = %d, want 5000", opts.count)
	}
	if opts.concurrency != 50 {
		t.Fatalf("concurrency = %d, want 50", opts.concurrency)
	}
	if opts.timeout.String() != "5s" {
		t.Fatalf("timeout = %s, want 5s", opts.timeout)
	}
	if opts.rawURL != m.configURL {
		t.Fatal("rawURL was not preserved")
	}
	if opts.fromFile {
		t.Fatal("fromFile = true, want random Cloudflare IPs")
	}
}

func TestResolvePhase1OptionsFromFile(t *testing.T) {
	m := NewApp("test")
	m.configIPMode = 1
	opts := m.resolvePhase1Options()
	if !opts.fromFile {
		t.Fatal("fromFile = false, want true")
	}
}

func TestPhase1TargetTotalUsesProviderCapacity(t *testing.T) {
	m := NewApp("test")
	m.applySelectedProvider(provider.Gcore)
	m.configSelectedPorts = map[int]bool{443: true}

	if got := m.phase1TargetTotal(1000); got != 978 {
		t.Fatalf("phase1 target = %d, want 978", got)
	}
}

func TestPhase1TargetTotalUsesFastlyRequestedCount(t *testing.T) {
	m := NewApp("test")
	m.applySelectedProvider(provider.Fastly)
	m.configSelectedPorts = map[int]bool{443: true}

	if got := m.phase1TargetTotal(1000); got != 1000 {
		t.Fatalf("phase1 target = %d, want 1000", got)
	}
}

func TestResolveConfigPortsMultiSelect(t *testing.T) {
	m := NewApp("test")
	m.configURL = "vless://12345678-1234-1234-1234-123456789abc@example.com:443?encryption=none&security=tls&type=ws&host=example.com&path=%2F#test"
	m.configSelectedPorts = map[int]bool{443: true, 8443: true}

	got := m.resolveConfigPorts()
	want := []string{"443", "8443"}
	parts := make([]string, len(got))
	for i, port := range got {
		parts[i] = strconv.Itoa(port)
	}
	if strings.Join(parts, ",") != strings.Join(want, ",") {
		t.Fatalf("ports = %v, want %v", got, want)
	}
}

func TestConfigPhase1EscWithHealthyConfigStartsPhase2(t *testing.T) {
	m := NewApp("test")
	m.page = PageConfigPhase1
	m.configRunID = 42
	m.configURL = "vless://12345678-1234-1234-1234-123456789abc@example.com:443?encryption=none&security=tls&type=ws&host=example.com&path=%2F#test"
	m.configPhase1Results = []*result.Result{
		{
			IP:           net.ParseIP("92.223.124.41"),
			Port:         443,
			Provider:     "gcore",
			ProbeMode:    "http",
			Latencies:    []time.Duration{100 * time.Millisecond},
			TLSOk:        true,
			HTTPStatus:   200,
			VerifiedHTTP: true,
		},
	}

	next, cmd := m.handleConfigPhase1Key(tea.KeyMsg{Type: tea.KeyEsc})
	got := next.(AppModel)
	if got.page != PageConfigPhase2 {
		t.Fatalf("page = %v, want PageConfigPhase2", got.page)
	}
	if !got.configScanning || got.configDone {
		t.Fatalf("configScanning/configDone = %t/%t, want true/false", got.configScanning, got.configDone)
	}
	if got.configTotal != 1 {
		t.Fatalf("configTotal = %d, want 1", got.configTotal)
	}
	if !got.configPhase1Finalized {
		t.Fatal("configPhase1Finalized = false, want true")
	}
	if cmd == nil {
		t.Fatal("expected Phase 2 command")
	}
}

func TestConfigPhase1EscWithoutHealthyIgnoresLateDone(t *testing.T) {
	m := NewApp("test")
	m.page = PageConfigPhase1
	m.configRunID = 99
	m.configURL = "vless://12345678-1234-1234-1234-123456789abc@example.com:443?encryption=none&security=tls&type=xhttp&host=example.com&path=%2F#test"

	next, cmd := m.handleConfigPhase1Key(tea.KeyMsg{Type: tea.KeyEsc})
	got := next.(AppModel)
	if cmd != nil {
		t.Fatal("cmd != nil, want nil")
	}
	if got.page != PageHome {
		t.Fatalf("page = %v, want PageHome", got.page)
	}
	if !got.configPhase1Finalized {
		t.Fatal("configPhase1Finalized = false, want true")
	}

	next, cmd = got.Update(ConfigPhase1DoneMsg{RunID: 99})
	got = next.(AppModel)
	if cmd != nil {
		t.Fatal("late done cmd != nil, want nil")
	}
	if got.page != PageHome {
		t.Fatalf("late done page = %v, want PageHome", got.page)
	}
	if got.configScanning || got.configDone {
		t.Fatalf("configScanning/configDone = %t/%t, want false/false", got.configScanning, got.configDone)
	}
}

func TestConfigPhase2EscIgnoresLateProgressAndDone(t *testing.T) {
	m := NewApp("test")
	m.page = PageConfigPhase2
	m.configRunID = 7
	m.configScanning = true
	m.configTotal = 50

	next, cmd := m.handleScanWithConfigKey(tea.KeyMsg{Type: tea.KeyEsc})
	got := next.(AppModel)
	if cmd != nil {
		t.Fatal("cmd != nil, want nil")
	}
	if got.page != PageHome {
		t.Fatalf("page = %v, want PageHome", got.page)
	}
	if got.configScanning || got.configDone {
		t.Fatalf("configScanning/configDone = %t/%t, want false/false", got.configScanning, got.configDone)
	}

	next, _ = got.Update(ConfigProgressMsg{
		RunID:  7,
		Result: &xraytest.ValidationResult{Success: true},
		Done:   1,
		Total:  50,
	})
	got = next.(AppModel)
	if len(got.configResults) != 0 {
		t.Fatalf("late progress appended %d results, want 0", len(got.configResults))
	}

	next, _ = got.Update(ConfigDoneMsg{RunID: 7})
	got = next.(AppModel)
	if got.configDone {
		t.Fatal("late done set configDone=true, want false")
	}
}

func TestFastlyConfigPhase1DoneWithNoHealthyStillStartsCanaryPhase2(t *testing.T) {
	m := NewApp("test")
	m.applySelectedProvider(provider.Fastly)
	m.page = PageConfigPhase1
	m.configURL = "vless://12345678-1234-1234-1234-123456789abc@example.com:443?encryption=none&security=tls&type=xhttp&host=example.com&path=%2F#test"

	next, cmd := m.finishConfigPhase1("done")
	got := next.(AppModel)
	if got.page != PageConfigPhase2 {
		t.Fatalf("page = %v, want PageConfigPhase2", got.page)
	}
	if !got.configScanning || got.configDone {
		t.Fatalf("configScanning/configDone = %t/%t, want true/false", got.configScanning, got.configDone)
	}
	if got.configTotal != 1 {
		t.Fatalf("configTotal = %d, want 1 canary candidate", got.configTotal)
	}
	if cmd == nil {
		t.Fatal("expected Phase 2 command")
	}
}

func TestPhase2CandidatesForGcorePrependsCanary(t *testing.T) {
	cfg := &xraytest.VLESSConfig{Port: 443}
	topIPs := []*result.Result{
		{IP: net.ParseIP("92.223.124.41"), Port: 443, Provider: "gcore"},
	}

	got := phase2CandidatesForProvider(provider.Gcore, cfg, topIPs)
	if len(got) != 2 {
		t.Fatalf("candidates = %d, want 2", len(got))
	}
	wantCanary := provider.DiagnosticCanaryIP(provider.Gcore)
	if got[0].IP.String() != wantCanary || got[0].Port != 443 {
		t.Fatalf("first candidate = %s:%d, want %s:443", got[0].IP, got[0].Port, wantCanary)
	}
	if got[1] != topIPs[0] {
		t.Fatal("original candidate was not preserved after canary")
	}
}

func TestPhase2CandidatesForGcoreDoesNotDuplicateCanary(t *testing.T) {
	cfg := &xraytest.VLESSConfig{Port: 443}
	topIPs := []*result.Result{
		{IP: net.ParseIP(provider.DiagnosticCanaryIP(provider.Gcore)), Port: 443, Provider: "gcore"},
	}

	got := phase2CandidatesForProvider(provider.Gcore, cfg, topIPs)
	if len(got) != 1 {
		t.Fatalf("candidates = %d, want 1", len(got))
	}
	if got[0] != topIPs[0] {
		t.Fatal("existing canary candidate should be reused")
	}
}

func TestPhase2CandidatesForFastlyPrependsCanary(t *testing.T) {
	cfg := &xraytest.VLESSConfig{Port: 443}
	topIPs := []*result.Result{
		{IP: net.ParseIP("151.101.1.1"), Port: 443, Provider: "fastly"},
	}

	got := phase2CandidatesForProvider(provider.Fastly, cfg, topIPs)
	if len(got) != 2 {
		t.Fatalf("candidates = %d, want 2", len(got))
	}
	wantCanary := provider.DiagnosticCanaryIP(provider.Fastly)
	if got[0].IP.String() != wantCanary || got[0].Port != 443 {
		t.Fatalf("first candidate = %s:%d, want %s:443", got[0].IP, got[0].Port, wantCanary)
	}
	if got[1] != topIPs[0] {
		t.Fatal("original candidate was not preserved after canary")
	}
}

func TestPhase2CandidatesForFastlyCanRunWithNoHealthyIPs(t *testing.T) {
	cfg := &xraytest.VLESSConfig{Port: 443}
	got := phase2CandidatesForProvider(provider.Fastly, cfg, nil)
	if len(got) != 1 {
		t.Fatalf("candidates = %d, want 1", len(got))
	}
	if got[0].IP.String() != provider.DiagnosticCanaryIP(provider.Fastly) {
		t.Fatalf("candidate = %s, want Fastly canary", got[0].IP)
	}
}

func TestPhase2CandidatesForCloudFrontDoesNotAddGcoreCanary(t *testing.T) {
	cfg := &xraytest.VLESSConfig{Port: 443}
	topIPs := []*result.Result{
		{IP: net.ParseIP("13.32.0.1"), Port: 443, Provider: "cloudfront"},
	}

	got := phase2CandidatesForProvider(provider.CloudFront, cfg, topIPs)
	if len(got) != 1 {
		t.Fatalf("candidates = %d, want 1", len(got))
	}
	if got[0] != topIPs[0] {
		t.Fatal("cloudfront candidates should be unchanged")
	}
}

func TestLoadDefaultIPsFileFindsWorkingDirectoryFile(t *testing.T) {
	dir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if err := writeIPsFile(filepath.Join(dir, "ips.txt"), []string{"104.18.1.1", "104.18.1.2"}); err != nil {
		t.Fatal(err)
	}

	ips, err := loadDefaultIPsFile()
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 {
		t.Fatalf("loaded %d IPs, want 2", len(ips))
	}
}

func TestWorkingIPsOnlyIncludesSuccessfulValidationResults(t *testing.T) {
	got := workingIPs([]*xraytest.ValidationResult{
		{IP: "104.18.1.1", Success: true},
		{IP: "104.18.1.2", Success: false},
		{IP: "104.18.1.1", Success: true},
		nil,
		{IP: "", Success: true},
	})
	want := []string{"104.18.1.1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("working IPs = %v, want %v", got, want)
	}
}

func TestWriteIPsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ips.txt")
	if err := writeIPsFile(path, []string{"104.18.1.1", "104.18.1.2"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), "104.18.1.1\n104.18.1.2\n"; got != want {
		t.Fatalf("file contents = %q, want %q", got, want)
	}
}

func TestCopyWorkingIPsNoSuccesses(t *testing.T) {
	m := AppModel{
		configResults: []*xraytest.ValidationResult{
			{IP: "104.18.1.2", Success: false},
		},
	}
	if got := m.copyWorkingIPs(); got != "no working endpoints to copy" {
		t.Fatalf("message = %q", got)
	}
}

func TestFormatValidationSpeed(t *testing.T) {
	if got := formatValidationSpeed(0); got != "n/a" {
		t.Fatalf("zero throughput = %q, want n/a", got)
	}
	// 1.25 MiB/s ~= 10.5 Mbps
	if got := formatValidationSpeed(1.25 * 1024 * 1024); got != "10.5 Mbps" {
		t.Fatalf("throughput formatting = %q, want 10.5 Mbps", got)
	}
}

func TestFormatValidationLatency(t *testing.T) {
	if got := formatValidationLatency(250 * time.Millisecond); got != "250ms" {
		t.Fatalf("latency = %q, want 250ms", got)
	}
	if got := formatValidationLatency(1500 * time.Millisecond); got != "1.5s" {
		t.Fatalf("latency = %q, want 1.5s", got)
	}
}

func TestWorkingEndpointsIncludePorts(t *testing.T) {
	got := workingEndpoints([]*xraytest.ValidationResult{
		{IP: "104.18.1.1", Port: 443, Success: true},
		{IP: "104.18.1.1", Port: 8443, Success: true},
		{IP: "104.18.1.2", Port: 443, Success: false},
	})
	want := []string{"104.18.1.1:443", "104.18.1.1:8443"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("working endpoints = %v, want %v", got, want)
	}
}

func TestWorkingValidationDetailsIncludesMetrics(t *testing.T) {
	got := workingValidationDetails([]*xraytest.ValidationResult{
		{IP: "104.18.1.1", Port: 443, Transport: "ws", Throughput: 1.25 * 1024 * 1024, Latency: 250 * time.Millisecond, Success: true},
		{IP: "104.18.1.2", Port: 443, Transport: "ws", Success: false},
	})
	want := "endpoint,type,speed,latency,status\n104.18.1.1:443,ws,10.5 Mbps,250ms,ok\n"
	if got != want {
		t.Fatalf("details = %q, want %q", got, want)
	}
}

func TestGenericScanCopyDoesNotExportHealthyIPs(t *testing.T) {
	m := AppModel{page: PageResults}
	next, _ := m.handleResultsKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	got := next.(AppModel).statusMsg
	if !strings.Contains(got, "Find Working IPs") {
		t.Fatalf("generic copy message = %q", got)
	}
}
