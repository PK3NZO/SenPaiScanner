package ui

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/matinsenpai/senpaiscanner/internal/debuglog"
	"github.com/matinsenpai/senpaiscanner/internal/engine"
	"github.com/matinsenpai/senpaiscanner/internal/ipsrc"
	"github.com/matinsenpai/senpaiscanner/internal/output"
	"github.com/matinsenpai/senpaiscanner/internal/prober"
	"github.com/matinsenpai/senpaiscanner/internal/provider"
	"github.com/matinsenpai/senpaiscanner/internal/result"
	"github.com/matinsenpai/senpaiscanner/internal/xraytest"
)

// scanCancel holds the cancel function for the active scan so the TUI can
// abort it when the user presses esc/q.
var scanCancel context.CancelFunc
var scanIDCounter atomic.Int64

func nextScanID() int64 { return scanIDCounter.Add(1) }

// StartScanCmd builds a tea.Cmd that runs the scan engine in the background,
// sending ResultMsg and StatsMsg messages to the Bubble Tea program.
func StartScanCmd(cfg ScanConfig, scanID int64) tea.Cmd {
	return func() tea.Msg {
		go func() {
			defer debuglog.Recover("runScan")
			runScan(cfg, scanID)
		}()
		return nil
	}
}

// CancelScanCmd cancels the running scan.
func CancelScanCmd() tea.Cmd {
	return func() tea.Msg {
		if scanCancel != nil {
			debuglog.Printf("scan_cancel_requested")
			scanCancel()
		}
		return nil
	}
}

// StartTestCmd runs the test pass against a file of IPs.
func StartTestCmd(ipFile string, kind provider.Kind, scanID int64) tea.Cmd {
	return func() tea.Msg {
		go func() {
			defer debuglog.Recover("runTest")
			runTest(ipFile, kind, scanID)
		}()
		return nil
	}
}

// StartColosCmd discovers accessible provider PoPs.
func StartColosCmd(kind provider.Kind, scanID int64) tea.Cmd {
	return func() tea.Msg {
		go func() {
			defer debuglog.Recover("runColos")
			runColos(kind, scanID)
		}()
		return nil
	}
}

// prog is set by main before launching the Bubble Tea program so the
// background goroutines can send messages back.
var prog *tea.Program

// SetProgram must be called before any scan command is started.
func SetProgram(p *tea.Program) { prog = p }

// ---------------------------------------------------------------------------
// Background runners
// ---------------------------------------------------------------------------

func runScan(cfg ScanConfig, scanID int64) {
	debuglog.Printf("run_scan_start scan_id=%d provider=%s count=%s concurrency=%s timeout=%s mode=%s port=%s use_v4=%t use_v6=%t cidr_set=%t",
		scanID, cfg.Provider, cfg.Count, cfg.Concurrency, cfg.Timeout, cfg.Mode, cfg.Port, cfg.UseV4, cfg.UseV6, strings.TrimSpace(cfg.CIDR) != "")
	count, _ := strconv.Atoi(cfg.Count)
	concurrency, _ := strconv.Atoi(cfg.Concurrency)
	if concurrency <= 0 {
		concurrency = 50
	}
	timeout := parseTimeout(cfg.Timeout, 5*time.Second)
	tries, _ := strconv.Atoi(cfg.Tries)
	if tries <= 0 {
		tries = 4
	}
	port, _ := strconv.Atoi(cfg.Port)
	if port <= 0 {
		port = 443
	}

	mode, err := prober.ParseMode(cfg.Mode)
	if err != nil {
		mode = prober.ModeHTTP
	}
	kind := provider.Normalize(cfg.Provider)

	var extra []string
	for _, c := range strings.Split(cfg.CIDR, ",") {
		c = strings.TrimSpace(c)
		if c != "" {
			extra = append(extra, c)
		}
	}

	useBuiltin := len(extra) == 0
	src, err := ipsrc.NewWithOptions(cfg.UseV4, cfg.UseV6, extra, ipsrc.Options{UseBuiltin: useBuiltin, Provider: kind})
	if err != nil {
		sendError(scanID, fmt.Sprintf("Scan setup failed: %v", err))
		sendDone(scanID)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	scanCancel = cancel
	defer cancel()

	engCfg := engine.Config{
		Concurrency: concurrency,
		ProbeConfig: prober.Config{
			Port:             port,
			Provider:         kind,
			Mode:             mode,
			Tries:            tries,
			Timeout:          timeout,
			SNI:              cfg.SNI,
			SpeedBytes:       speedSampleForMode(kind, mode),
			RequireWebSocket: mode == prober.ModeHTTP && provider.SupportsWebSocketHold(kind) && speedSampleForMode(kind, mode) > 0,
		},
	}
	eng := engine.New(engCfg)

	coloSet := buildColoSet(cfg.ColoFilter)

	var writer *output.Writer
	if cfg.OutputFile != "" {
		fmt2 := output.DetectFormat(cfg.OutputFile)
		if w, e := output.New(cfg.OutputFile, fmt2); e == nil {
			writer = w
			defer writer.Close()
		} else {
			sendError(scanID, fmt.Sprintf("Output disabled: %v", e))
		}
	}

	ipStream := src.Stream(ctx, count)
	eng.Run(ctx, ipStream, func(r *result.Result) {
		if prog != nil {
			s := eng.Stats()
			prog.Send(StatsMsg{ScanID: scanID, Tested: s.Tested.Load(), Healthy: s.Healthy.Load(), Failed: s.Failed.Load(), InFlight: s.InFlight.Load()})
		}
		if !passesColoFilter(r, coloSet) {
			return
		}
		// Only healthy IPs go to the output file; writing every scanned IP
		// would flood the file with thousands of failed probes.
		if writer != nil && r.IsHealthy() {
			if err := writer.Write(r); err != nil {
				sendError(scanID, fmt.Sprintf("Output write failed: %v", err))
			}
		}
		if prog != nil {
			prog.Send(ResultMsg{ScanID: scanID, Result: r})
		}
	})

	debuglog.Printf("run_scan_done scan_id=%d tested=%d healthy=%d failed=%d", scanID, eng.Stats().Tested.Load(), eng.Stats().Healthy.Load(), eng.Stats().Failed.Load())
	sendDone(scanID)
}

func runTest(ipFile string, kind provider.Kind, scanID int64) {
	ips, err := loadIPs(ipFile)
	if err != nil {
		sendError(scanID, fmt.Sprintf("Test IPs failed: %v", err))
		sendDone(scanID)
		return
	}
	if len(ips) == 0 {
		sendError(scanID, fmt.Sprintf("Test IPs failed: no valid IPs found in %s", ipFile))
		sendDone(scanID)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	scanCancel = cancel
	defer cancel()

	engCfg := engine.Config{
		Concurrency: 20,
		ProbeConfig: prober.Config{
			Port:             443,
			Provider:         kind,
			Mode:             prober.ModeHTTP,
			Tries:            6,
			Timeout:          10 * time.Second,
			SNI:              provider.DefaultHTTPHost(kind),
			SpeedBytes:       speedSampleForMode(kind, prober.ModeHTTP),
			RequireWebSocket: provider.SupportsWebSocketHold(kind),
		},
	}
	eng := engine.New(engCfg)

	eng.RunList(ctx, ips, func(r *result.Result) {
		if prog != nil {
			s := eng.Stats()
			prog.Send(ResultMsg{ScanID: scanID, Result: r})
			prog.Send(StatsMsg{ScanID: scanID, Tested: s.Tested.Load(), Healthy: s.Healthy.Load(), Failed: s.Failed.Load(), InFlight: s.InFlight.Load()})
		}
	})

	sendDone(scanID)
}

func runColos(kind provider.Kind, scanID int64) {
	src, err := ipsrc.NewWithOptions(true, false, nil, ipsrc.Options{UseBuiltin: true, Provider: kind})
	if err != nil {
		sendError(scanID, fmt.Sprintf("Colo discovery failed: %v", err))
		sendColosDone(scanID)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	scanCancel = cancel
	defer cancel()

	engCfg := engine.Config{
		Concurrency: 80,
		ProbeConfig: prober.Config{
			Port:       443,
			Provider:   kind,
			Mode:       prober.ModeHTTP,
			Tries:      2,
			Timeout:    5 * time.Second,
			SpeedBytes: 0,
		},
	}
	eng := engine.New(engCfg)
	ipStream := src.Stream(ctx, 300)

	eng.Run(ctx, ipStream, func(r *result.Result) {
		if prog != nil {
			s := eng.Stats()
			prog.Send(StatsMsg{ScanID: scanID, Tested: s.Tested.Load(), Healthy: s.Healthy.Load(), Failed: s.Failed.Load(), InFlight: s.InFlight.Load()})
		}
		if !r.IsHealthy() || r.Colo == "" {
			return
		}
		if prog != nil {
			prog.Send(ResultMsg{ScanID: scanID, Result: r})
		}
	})

	sendColosDone(scanID)
}

func sendError(scanID int64, text string) {
	if prog != nil {
		prog.Send(ErrorMsg{ScanID: scanID, Text: text})
	}
}

func sendDone(scanID int64) {
	if prog != nil {
		prog.Send(DoneMsg{ScanID: scanID})
	}
}

func sendColosDone(scanID int64) {
	if prog != nil {
		prog.Send(ColosDoneMsg{ScanID: scanID})
	}
}

// runConfigPhase1 runs Phase 1 of "Scan with Config": a fast connectivity scan
// that finds healthy provider IPs (or validates IPs from a file), then signals
// the UI to start Phase 2 (xray validation) with the best candidates.
func runConfigPhase1(opts configPhase1Options) {
	debuglog.Printf("config_phase1_start provider=%s count=%d concurrency=%d timeout=%s from_file=%t ports=%v with_config=%t",
		opts.provider, opts.count, opts.concurrency, opts.timeout, opts.fromFile, opts.ports, strings.TrimSpace(opts.rawURL) != "")
	var probeCfg prober.Config
	var err error
	if strings.TrimSpace(opts.rawURL) == "" {
		probeCfg = defaultPhase1ProbeConfig(opts.timeout, opts.provider)
	} else {
		probeCfg, err = configProbeFromURL(opts.rawURL, opts.timeout, opts.provider)
		if err != nil {
			if prog != nil {
				prog.Send(ConfigPhase1ErrMsg{RunID: opts.runID, Err: fmt.Sprintf("invalid URL: %v", err)})
			}
			return
		}
	}
	debuglog.Printf("config_phase1_probe_config provider=%s mode=%s tries=%d timeout=%s sni_set=%t insecure=%t early_stop=%t",
		opts.provider, probeCfg.Mode, probeCfg.Tries, probeCfg.Timeout, probeCfg.SNI != "", probeCfg.InsecureSkipVerify, probeCfg.EarlyStop)
	ports := opts.ports
	if len(ports) == 0 {
		ports = []int{probeCfg.Port}
	}

	ctx, cancel := context.WithCancel(context.Background())
	scanCancel = cancel
	defer cancel()

	callback := func(r *result.Result) {
		debuglog.Printf("config_phase1_result endpoint=%s healthy=%t mode=%s provider=%s loss=%.1f avg_ms=%d status=%d colo=%s tls=%t ws=%t",
			formatEndpoint(r.IP.String(), r.Port), r.IsHealthy(), r.ProbeMode, r.Provider, r.Loss(), r.Avg().Milliseconds(), r.HTTPStatus, r.Colo, r.TLSOk, r.WSOk)
		if liveResultWriter != nil {
			liveResultWriter.AddPhase1(r)
		}
		if prog != nil {
			prog.Send(ConfigPhase1ResultMsg{RunID: opts.runID, Result: r})
		}
	}

	var ipStream <-chan net.IP
	neighbor := neighborScanOpts{}
	if opts.fromFile {
		ips, err := loadDefaultIPsFile()
		if err != nil {
			if prog != nil {
				prog.Send(ConfigPhase1ErrMsg{RunID: opts.runID, Err: err.Error()})
			}
			return
		}
		if len(ips) == 0 {
			if prog != nil {
				prog.Send(ConfigPhase1ErrMsg{RunID: opts.runID, Err: "ips.txt is empty — add one IP per line"})
			}
			return
		}
		ch := make(chan net.IP, len(ips))
		for _, ip := range ips {
			ch <- ip
		}
		close(ch)
		ipStream = ch
	} else {
		src, err := ipsrc.NewWithOptions(true, false, nil, ipsrc.Options{UseBuiltin: true, Provider: opts.provider})
		if err != nil {
			if prog != nil {
				prog.Send(ConfigPhase1DoneMsg{RunID: opts.runID})
			}
			return
		}
		ipStream = src.Stream(ctx, opts.count)
		ipStream = prependProviderCanary(ctx, opts.provider, ipStream)
		neighbor = neighborScanOpts{
			enabled:  true,
			nets:     src.IPv4Nets(),
			radius:   ipsrc.DefaultNeighborRadius,
			perHit:   ipsrc.DefaultNeighborPerHit,
			maxTotal: ipsrc.DefaultNeighborMaxTotal,
		}
	}
	maxProbes := 0
	if !opts.fromFile {
		maxProbes = opts.count * len(ports)
	}
	runConfigPortProbes(ctx, ipStream, ports, opts.concurrency, probeCfg, callback, neighbor, maxProbes)

	if prog != nil {
		prog.Send(ConfigPhase1DoneMsg{RunID: opts.runID})
	}
	debuglog.Printf("config_phase1_done provider=%s", opts.provider)
}

func prependProviderCanary(ctx context.Context, kind provider.Kind, ips <-chan net.IP) <-chan net.IP {
	if provider.Normalize(string(kind)) != provider.Fastly {
		return ips
	}
	canary := provider.DiagnosticCanaryIP(kind)
	if canary == "" {
		return ips
	}
	canaryIP := net.ParseIP(canary)
	if canaryIP == nil {
		return ips
	}
	debuglog.Printf("config_phase1_canary_enqueue provider=%s ip=%s", provider.Normalize(string(kind)), canary)
	ch := make(chan net.IP, 64)
	go func() {
		defer close(ch)
		sentCanary := false
		select {
		case <-ctx.Done():
			return
		case ch <- canaryIP:
			sentCanary = true
		}
		for ip := range ips {
			if sentCanary && ip.Equal(canaryIP) {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case ch <- ip:
			}
		}
	}()
	return ch
}

type configProbeJob struct {
	ip   net.IP
	port int
}

type activeConfigProbe struct {
	ip    net.IP
	port  int
	start time.Time
}

type neighborScanOpts struct {
	enabled  bool
	nets     []*net.IPNet
	radius   int
	perHit   int
	maxTotal int
}

func runConfigPortProbes(ctx context.Context, ips <-chan net.IP, ports []int, concurrency int, base prober.Config, callback func(*result.Result), neighbor neighborScanOpts, maxProbes int) {
	if concurrency <= 0 {
		concurrency = 50
	}
	if neighbor.enabled {
		if neighbor.radius <= 0 {
			neighbor.radius = ipsrc.DefaultNeighborRadius
		}
		if neighbor.perHit <= 0 {
			neighbor.perHit = ipsrc.DefaultNeighborPerHit
		}
		if neighbor.maxTotal <= 0 {
			neighbor.maxTotal = ipsrc.DefaultNeighborMaxTotal
		}
	}

	jobs := make(chan configProbeJob, concurrency*2)
	var pending int64
	var completed int64
	var neighborsQueued int64
	var inputDone atomic.Bool
	seen := make(map[string]struct{})
	submitted := 0
	var seenMu sync.Mutex
	active := make(map[int]activeConfigProbe)
	var activeMu sync.Mutex

	jobKey := func(ip net.IP, port int) string {
		return fmt.Sprintf("%s:%d", ip.String(), port)
	}

	atProbeLimit := func() bool {
		if maxProbes <= 0 {
			return false
		}
		seenMu.Lock()
		defer seenMu.Unlock()
		return submitted >= maxProbes
	}

	submittedCount := func() int {
		seenMu.Lock()
		defer seenMu.Unlock()
		return submitted
	}

	rollbackSubmit := func(key string) {
		seenMu.Lock()
		delete(seen, key)
		submitted--
		seenMu.Unlock()
		atomic.AddInt64(&pending, -1)
	}

	submit := func(ip net.IP, port int, block bool) bool {
		key := jobKey(ip, port)
		seenMu.Lock()
		if _, ok := seen[key]; ok {
			seenMu.Unlock()
			return false
		}
		if maxProbes > 0 && submitted >= maxProbes {
			seenMu.Unlock()
			return false
		}
		seen[key] = struct{}{}
		submitted++
		seenMu.Unlock()

		atomic.AddInt64(&pending, 1)
		if !block {
			select {
			case <-ctx.Done():
				rollbackSubmit(key)
				return false
			case jobs <- configProbeJob{ip: ip, port: port}:
				return true
			default:
				rollbackSubmit(key)
				return false
			}
		}
		select {
		case <-ctx.Done():
			rollbackSubmit(key)
			return false
		case jobs <- configProbeJob{ip: ip, port: port}:
			return true
		}
	}

	enqueueIP := func(ip net.IP) {
		for _, port := range ports {
			submit(ip, port, true)
		}
	}

	maybeEnqueueNeighbors := func(r *result.Result) {
		if ctx.Err() != nil || !neighbor.enabled || !r.IsHealthy() || len(neighbor.nets) == 0 {
			return
		}

		remaining := neighbor.maxTotal - int(atomic.LoadInt64(&neighborsQueued))
		if remaining <= 0 {
			return
		}
		limit := neighbor.perHit
		if limit > remaining {
			limit = remaining
		}

		for _, nip := range ipsrc.NeighborsAround(r.IP, neighbor.nets, neighbor.radius, limit) {
			if atomic.LoadInt64(&neighborsQueued) >= int64(neighbor.maxTotal) {
				break
			}
			added := 0
			for _, port := range ports {
				if submit(nip, port, false) {
					added++
				}
			}
			if added > 0 {
				atomic.AddInt64(&neighborsQueued, 1)
			}
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		workerID := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					atomic.AddInt64(&pending, -1)
					atomic.AddInt64(&completed, 1)
					continue
				}
				activeMu.Lock()
				active[workerID] = activeConfigProbe{ip: job.ip, port: job.port, start: time.Now()}
				activeMu.Unlock()
				started := time.Now()
				r := prober.Probe(ctx, job.ip, base.WithPort(job.port))
				elapsed := time.Since(started)
				activeMu.Lock()
				delete(active, workerID)
				activeMu.Unlock()
				if ctx.Err() != nil {
					atomic.AddInt64(&pending, -1)
					atomic.AddInt64(&completed, 1)
					continue
				}
				if elapsed > base.Timeout+500*time.Millisecond {
					debuglog.Printf("config_phase1_probe_slow endpoint=%s mode=%s duration=%s timeout=%s healthy=%t",
						formatEndpoint(job.ip.String(), job.port), base.Mode, elapsed.Round(time.Millisecond), base.Timeout, r.IsHealthy())
				}
				maybeEnqueueNeighbors(r)
				callback(r)
				atomic.AddInt64(&pending, -1)
				atomic.AddInt64(&completed, 1)
			}
		}()
	}

	stopStats := make(chan struct{})
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				debuglog.Printf("config_phase1_probe_stats event=ctx_done submitted=%d completed=%d pending=%d queue=%d neighbors=%d input_done=%t",
					submittedCount(), atomic.LoadInt64(&completed), atomic.LoadInt64(&pending), len(jobs), atomic.LoadInt64(&neighborsQueued), inputDone.Load())
				return
			case <-stopStats:
				return
			case <-ticker.C:
				now := time.Now()
				var slow []string
				activeMu.Lock()
				for _, p := range active {
					age := now.Sub(p.start)
					if age > base.Timeout+500*time.Millisecond {
						slow = append(slow, fmt.Sprintf("%s@%s", formatEndpoint(p.ip.String(), p.port), age.Round(time.Millisecond)))
						if len(slow) >= 12 {
							break
						}
					}
				}
				activeCount := len(active)
				activeMu.Unlock()
				debuglog.Printf("config_phase1_probe_stats submitted=%d completed=%d pending=%d active=%d queue=%d neighbors=%d input_done=%t slow=%q",
					submittedCount(), atomic.LoadInt64(&completed), atomic.LoadInt64(&pending), activeCount, len(jobs), atomic.LoadInt64(&neighborsQueued), inputDone.Load(), strings.Join(slow, ","))
			}
		}
	}()

	go func() {
		defer func() {
			inputDone.Store(true)
			for atomic.LoadInt64(&pending) > 0 {
				time.Sleep(20 * time.Millisecond)
			}
			close(jobs)
		}()

		for ip := range ips {
			if ctx.Err() != nil {
				return
			}
			if atProbeLimit() {
				return
			}
			enqueueIP(ip)
		}
	}()

	wg.Wait()
	close(stopStats)
	debuglog.Printf("config_phase1_probe_complete submitted=%d completed=%d pending=%d neighbors=%d input_done=%t",
		submittedCount(), atomic.LoadInt64(&completed), atomic.LoadInt64(&pending), atomic.LoadInt64(&neighborsQueued), inputDone.Load())
}

func defaultPhase1ProbeConfig(timeout time.Duration, kind provider.Kind) prober.Config {
	mode := prober.ModeHTTP
	speedBytes := speedSampleForMode(kind, prober.ModeHTTP)
	insecure := false
	if provider.Normalize(string(kind)) == provider.Fastly {
		mode = prober.ModeTLS
		speedBytes = 0
		insecure = true
	}
	return prober.Config{
		Port:               443,
		Provider:           kind,
		Mode:               mode,
		Tries:              3,
		Timeout:            timeout,
		SNI:                provider.DefaultHTTPHost(kind),
		SpeedBytes:         speedBytes,
		InsecureSkipVerify: insecure,
		EarlyStop:          true,
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func buildColoSet(raw string) map[string]bool {
	if raw == "" {
		return nil
	}
	set := make(map[string]bool)
	for _, c := range strings.Split(raw, ",") {
		c = strings.TrimSpace(strings.ToUpper(c))
		if c != "" {
			set[c] = true
		}
	}
	return set
}

func passesColoFilter(r *result.Result, set map[string]bool) bool {
	if set == nil {
		return true
	}
	return set[strings.ToUpper(r.Colo)]
}

func configProbeFromURL(rawURL string, timeout time.Duration, kind provider.Kind) (prober.Config, error) {
	cfg, err := xraytest.ParseProxyURL(rawURL)
	if err != nil {
		return prober.Config{}, err
	}

	switch provider.Normalize(string(kind)) {
	case provider.CloudFront, provider.Gcore, provider.Fastly:
		// Shared CDN edges are distribution/config specific. Provider-owned
		// list endpoints can reject otherwise usable edges, so config mode uses
		// a TLS reachability shortlist and lets Phase 2 validate the exact xray
		// config end-to-end.
		sni := cfg.SNI
		if sni == "" {
			sni = cfg.Host
		}
		if sni == "" {
			sni = provider.DefaultHTTPHost(kind)
		}
		return prober.Config{
			Port:               cfg.Port,
			Provider:           kind,
			Mode:               prober.ModeTLS,
			Tries:              1,
			Timeout:            timeout,
			SNI:                sni,
			InsecureSkipVerify: true,
			EarlyStop:          true,
		}, nil
	}

	sni := cfg.SNI
	if sni == "" {
		sni = cfg.Host
	}

	probeCfg := prober.Config{
		Port:               cfg.Port,
		Provider:           kind,
		Mode:               prober.ModeHTTP,
		Tries:              3,
		Timeout:            timeout,
		SNI:                sni,
		InsecureSkipVerify: true,
		EarlyStop:          true,
	}
	if cfg.Network == "ws" {
		probeCfg.WebSocketHost = cfg.Host
		probeCfg.WebSocketPath = cfg.Path
		probeCfg.RequireWebSocket = provider.SupportsWebSocketHold(kind)
	}
	return probeCfg, nil
}

func ipsFileSearchPaths() []string {
	seen := make(map[string]struct{})
	add := func(paths *[]string, path string) {
		if path == "" {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		*paths = append(*paths, path)
	}

	var paths []string
	if wd, err := os.Getwd(); err == nil {
		add(&paths, filepath.Join(wd, "ips.txt"))
	}
	if exe, err := os.Executable(); err == nil {
		add(&paths, filepath.Join(filepath.Dir(exe), "ips.txt"))
	}
	return paths
}

func loadDefaultIPsFile() ([]net.IP, error) {
	for _, path := range ipsFileSearchPaths() {
		ips, err := loadIPs(path)
		if err == nil {
			return ips, nil
		}
	}
	return nil, fmt.Errorf("ips.txt not found — place it next to the binary or run folder")
}

func loadIPs(path string) ([]net.IP, error) {
	var f *os.File
	var err error
	if path == "" || path == "-" {
		f = os.Stdin
	} else {
		f, err = os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", path, err)
		}
		defer f.Close()
	}
	var ips []net.IP
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "ip") {
			continue
		}
		field := strings.SplitN(line, ",", 2)[0]
		if ip := net.ParseIP(strings.TrimSpace(field)); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips, sc.Err()
}

func speedSampleForMode(kind provider.Kind, mode prober.Mode) int64 {
	if mode != prober.ModeHTTP || !provider.SupportsDownload(kind) {
		return 0
	}
	// 64 KB is enough to detect IPs that stall on real data while still
	// completing reliably on restricted/high-latency networks. 256 KB was too
	// large: on throttled connections it consistently timed out, making every
	// IP appear unhealthy even when the trace GET succeeded fine.
	return 64 * 1024
}

func parseTimeout(raw string, fallback time.Duration) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	if timeout, err := time.ParseDuration(raw); err == nil {
		return timeout
	}
	if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return fallback
}
