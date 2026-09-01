package modsecurity

import (
	"context"
	"log/slog"
	"testing"
)

func TestPrepare_LogLevelDefaultInfo(t *testing.T) {
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf"
	cfg.LogLevel = ""
	if err := Prepare(cfg, "t"); err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != LogLevelInfo {
		t.Fatalf("LogLevel = %q, want info", cfg.LogLevel)
	}
}

func TestPrepare_LogLevelNormalizesCase(t *testing.T) {
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf"
	cfg.LogLevel = "DEBUG"
	if err := Prepare(cfg, "t"); err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != LogLevelDebug {
		t.Fatalf("LogLevel = %q, want debug", cfg.LogLevel)
	}
}

func TestPrepare_LogLevelRejectsUnknown(t *testing.T) {
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf"
	cfg.LogLevel = "trace"
	if err := Prepare(cfg, "t"); err == nil {
		t.Fatal("expected error for logLevel=trace")
	}
}

func TestNewLogger_InfoHidesDebug(t *testing.T) {
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf"
	if err := Prepare(cfg, "t"); err != nil {
		t.Fatal(err)
	}
	logger := NewLogger(cfg)
	if logger.Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("info logger must not enable debug")
	}
	if !logger.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("info logger must enable info")
	}
}

func TestNewLogger_DebugEnablesDebug(t *testing.T) {
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf"
	cfg.LogLevel = LogLevelDebug
	if err := Prepare(cfg, "t"); err != nil {
		t.Fatal(err)
	}
	logger := NewLogger(cfg)
	if !logger.Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("debug logger must enable debug")
	}
}
