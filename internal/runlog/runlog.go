package runlog

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/matinsenpai/senpaiscanner/internal/provider"
	"github.com/matinsenpai/senpaiscanner/internal/result"
	"github.com/matinsenpai/senpaiscanner/internal/xraytest"
)

type Session struct {
	Dir string

	mu sync.Mutex
}

func NewConfigSession(baseDir string, kind provider.Kind, method string, startedAt time.Time) (*Session, error) {
	if strings.TrimSpace(baseDir) == "" {
		baseDir = "results"
	}
	method = sanitize(method)
	if method == "" {
		method = "unknown"
	}
	dirName := fmt.Sprintf("%s-testwithconfig-%s-%s",
		strings.ToLower(string(provider.Normalize(string(kind)))),
		method,
		startedAt.Format("20060102-150405"),
	)
	dir := filepath.Join(baseDir, dirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Session{Dir: dir}, nil
}

func (s *Session) WriteMetadata(lines []string) error {
	return s.appendLines("meta.txt", lines...)
}

func (s *Session) AppendPhase1Result(r *result.Result) error {
	if r == nil {
		return nil
	}
	line := fmt.Sprintf("%s  ip=%-16s healthy=%-5t loss=%5.1f avg=%5dms jitter=%5dms colo=%s status=%d ws=%t",
		time.Now().Format("15:04:05"),
		r.IP.String(),
		r.IsHealthy(),
		r.Loss(),
		r.Avg().Milliseconds(),
		r.Jitter().Milliseconds(),
		blankDash(r.Colo),
		r.HTTPStatus,
		r.WSOk,
	)
	return s.appendLines("phase1-live.txt", line)
}

func (s *Session) WritePhase1Healthy(results []*result.Result) error {
	lines := []string{
		fmt.Sprintf("generated_at=%s", time.Now().Format(time.RFC3339)),
		fmt.Sprintf("healthy_count=%d", len(results)),
		"",
	}
	for _, r := range results {
		if r == nil {
			continue
		}
		lines = append(lines, fmt.Sprintf("ip=%-16s avg=%5dms loss=%5.1f jitter=%5dms colo=%s status=%d ws=%t",
			r.IP.String(),
			r.Avg().Milliseconds(),
			r.Loss(),
			r.Jitter().Milliseconds(),
			blankDash(r.Colo),
			r.HTTPStatus,
			r.WSOk,
		))
	}
	return s.writeLines("phase1-healthy.txt", lines...)
}

func (s *Session) WritePhase1Candidates(results []*result.Result) error {
	lines := []string{
		fmt.Sprintf("generated_at=%s", time.Now().Format(time.RFC3339)),
		fmt.Sprintf("candidate_count=%d", len(results)),
		"",
	}
	for _, r := range results {
		if r == nil {
			continue
		}
		lines = append(lines, fmt.Sprintf("ip=%-16s avg=%5dms loss=%5.1f jitter=%5dms colo=%s",
			r.IP.String(),
			r.Avg().Milliseconds(),
			r.Loss(),
			r.Jitter().Milliseconds(),
			blankDash(r.Colo),
		))
	}
	return s.writeLines("phase1-candidates.txt", lines...)
}

func (s *Session) AppendPhase2Result(r *xraytest.ValidationResult) error {
	if r == nil {
		return nil
	}
	speed := "—"
	if r.Throughput > 0 {
		speed = fmt.Sprintf("%.1fMbps", r.Throughput*8/1000000)
	}
	status := "fail"
	if r.Success {
		status = "ok"
	}
	line := fmt.Sprintf("%s  ip=%-16s transport=%-8s status=%-4s latency=%5dms speed=%-10s retries=%d error=%s",
		time.Now().Format("15:04:05"),
		r.IP,
		blankDash(r.Transport),
		status,
		r.Latency.Milliseconds(),
		speed,
		r.Retries,
		blankDash(r.Error),
	)
	return s.appendLines("phase2-live.txt", line)
}

func (s *Session) appendLines(name string, lines ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.Dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, line := range lines {
		if _, err := fmt.Fprintln(f, line); err != nil {
			return err
		}
	}
	return nil
}

func (s *Session) writeLines(name string, lines ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.Dir, name)
	content := strings.Join(lines, "\n")
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func sanitize(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	raw = strings.ReplaceAll(raw, " ", "-")
	var b strings.Builder
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		}
	}
	return strings.Trim(b.String(), "-_")
}

func blankDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "—"
	}
	return v
}
