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

func TestPrepare_ZeroTimeoutMillisDefaults(t *testing.T) {
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf"
	cfg.TimeoutMillis = 0
	if err := Prepare(cfg, "t"); err != nil {
		t.Fatal(err)
	}
	if cfg.TimeoutMillis != 2000 {
		t.Fatalf("TimeoutMillis = %d, want 2000", cfg.TimeoutMillis)
	}
}

func TestPrepare_RejectsNegativeTimeoutMillis(t *testing.T) {
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf"
	cfg.TimeoutMillis = -1
	if err := Prepare(cfg, "t"); err == nil {
		t.Fatal("expected error for timeoutMillis=-1")
	}
}

func TestPrepare_RejectsNegativeMaxBodySizeBytes(t *testing.T) {
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf"
	cfg.MaxBodySizeBytes = -1
	if err := Prepare(cfg, "t"); err == nil {
		t.Fatal("expected error for maxBodySizeBytes=-1")
	}
}

func TestPrepare_RejectsURLWithoutScheme(t *testing.T) {
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "waf:80"
	if err := Prepare(cfg, "t"); err == nil {
		t.Fatal("expected error for modSecurityUrl=waf:80")
	}
}

func TestPrepare_RejectsURLWithPath(t *testing.T) {
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf:80/modsec"
	if err := Prepare(cfg, "t"); err == nil {
		t.Fatal("expected error for modSecurityUrl with path")
	}
}

func TestPrepare_TrimsTrailingSlashOnURL(t *testing.T) {
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf:80/"
	if err := Prepare(cfg, "t"); err != nil {
		t.Fatal(err)
	}
	if cfg.ModSecurityUrl != "http://waf:80" {
		t.Fatalf("ModSecurityUrl = %q, want http://waf:80", cfg.ModSecurityUrl)
	}
}

func TestNewLogger_InfoHidesDebug(t *testing.T) {
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf"
	if err := Prepare(cfg, "t"); err != nil {
		t.Fatal(err)
	}
	logger := NewLogger("t", cfg)
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
	logger := NewLogger("t", cfg)
	if !logger.Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("debug logger must enable debug")
	}
}
