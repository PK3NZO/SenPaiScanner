package debuglog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

type Settings struct {
	DebugMode bool `json:"debug_mode"`
}

var (
	mu       sync.Mutex
	enabled  bool
	file     *os.File
	logPath  string
	started  time.Time
	settings Settings
)

func LoadSettings() Settings {
	path, err := settingsPath()
	if err != nil {
		return Settings{}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Settings{}
	}
	var s Settings
	if err := json.Unmarshal(b, &s); err != nil {
		return Settings{}
	}
	settings = s
	return s
}

func SaveSettings(s Settings) error {
	path, err := settingsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	settings = s
	return os.Rename(tmp, path)
}

func StartSession(on bool, version string, args []string) error {
	mu.Lock()
	defer mu.Unlock()

	closeLocked("replaced")
	enabled = on
	started = time.Now()
	logPath = ""
	if !enabled {
		return nil
	}

	dir := filepath.Join(".", "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		enabled = false
		return err
	}
	path := filepath.Join(dir, started.Format("20060102-150405")+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		enabled = false
		return err
	}
	file = f
	logPath = path
	writeLocked("session_start version=%s pid=%d args=%q settings_path=%q",
		version, os.Getpid(), strings.Join(args, " "), mustSettingsPath())
	return nil
}

func Enabled() bool {
	mu.Lock()
	defer mu.Unlock()
	return enabled
}

func Path() string {
	mu.Lock()
	defer mu.Unlock()
	return logPath
}

func Printf(format string, args ...any) {
	mu.Lock()
	defer mu.Unlock()
	if !enabled || file == nil {
		return
	}
	writeLocked(format, args...)
}

func Close(reason string) {
	mu.Lock()
	defer mu.Unlock()
	closeLocked(reason)
}

func Recover(scope string) {
	if v := recover(); v != nil {
		Printf("panic scope=%s value=%v stack=%q", scope, v, string(debug.Stack()))
		panic(v)
	}
}

func settingsPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "SenPaiScanner", "settings.json"), nil
}

func mustSettingsPath() string {
	path, err := settingsPath()
	if err != nil {
		return ""
	}
	return path
}

func writeLocked(format string, args ...any) {
	if file == nil {
		return
	}
	line := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintf(file, "%s %s\n", time.Now().Format(time.RFC3339Nano), line)
	_ = file.Sync()
}

func closeLocked(reason string) {
	if file == nil {
		return
	}
	writeLocked("session_end reason=%s duration=%s", reason, time.Since(started).Round(time.Millisecond))
	_ = file.Close()
	file = nil
}
