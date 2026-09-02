package modsecurity

import (
	"context"
	"log/slog"
	"testing"
)

func TestPrepare_HealthTrackerOmittedDefaults(t *testing.T) {
	cfg := &Config{
		ModSecurityUrl:                "http://waf",
		UnhealthyWafBackOffPeriodSecs: 30,
	}
	if err := Prepare(cfg, "t"); err != nil {
		t.Fatal(err)
	}
	if cfg.UnhealthyWafFailureThreshold != 5 {
		t.Fatalf("UnhealthyWafFailureThreshold = %d, want 5", cfg.UnhealthyWafFailureThreshold)
	}
	if cfg.UnhealthyWafFailureWindowSecs != 10 {
		t.Fatalf("UnhealthyWafFailureWindowSecs = %d, want 10", cfg.UnhealthyWafFailureWindowSecs)
	}
}

func TestPrepare_KeepsExplicitThreshold(t *testing.T) {
	cfg := &Config{
		ModSecurityUrl:                "http://waf",
		UnhealthyWafBackOffPeriodSecs: 30,
		UnhealthyWafFailureThreshold:  1,
	}
	if err := Prepare(cfg, "t"); err != nil {
		t.Fatal(err)
	}
	if cfg.UnhealthyWafFailureThreshold != 1 {
		t.Fatalf("UnhealthyWafFailureThreshold = %d, want 1", cfg.UnhealthyWafFailureThreshold)
	}
	if cfg.UnhealthyWafFailureWindowSecs != 10 {
		t.Fatalf("UnhealthyWafFailureWindowSecs = %d, want 10", cfg.UnhealthyWafFailureWindowSecs)
	}
}

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

// TestPrepare_RejectsRemainingNegativeNumericFields checks Prepare fails for every leftover negative numeric field.
func TestPrepare_RejectsRemainingNegativeNumericFields(t *testing.T) {
	tests := []struct {
		name string
		set  func(*Config)
	}{
		{"unhealthyWafBackOffPeriodSecs", func(c *Config) { c.UnhealthyWafBackOffPeriodSecs = -1 }},
		{"unhealthyWafFailureThreshold", func(c *Config) { c.UnhealthyWafFailureThreshold = -1 }},
		{"unhealthyWafFailureWindowSecs", func(c *Config) { c.UnhealthyWafFailureWindowSecs = -1 }},
		{"maxConnsPerHost", func(c *Config) { c.MaxConnsPerHost = -1 }},
		{"maxIdleConnsPerHost", func(c *Config) { c.MaxIdleConnsPerHost = -1 }},
		{"responseHeaderTimeoutMillis", func(c *Config) { c.ResponseHeaderTimeoutMillis = -1 }},
		{"expectContinueTimeoutMillis", func(c *Config) { c.ExpectContinueTimeoutMillis = -1 }},
		{"maxBodySizeBytesForPool", func(c *Config) { c.MaxBodySizeBytesForPool = -1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := CreateConfig()
			cfg.ModSecurityUrl = "http://waf"
			tt.set(cfg)
			if err := Prepare(cfg, "t"); err == nil {
				t.Fatalf("expected error for %s=-1", tt.name)
			}
		})
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

func TestPrepare_NilDenyVerbsWithBodyGetsDefault(t *testing.T) {
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf"
	cfg.DenyVerbsWithBody = nil
	if err := Prepare(cfg, "t"); err != nil {
		t.Fatal(err)
	}
	if len(cfg.DenyVerbsWithBody) == 0 {
		t.Fatal("nil denyVerbsWithBody must become the CreateConfig default")
	}
}

func TestPrepare_EmptyDenyVerbsWithBodyStaysEmpty(t *testing.T) {
	cfg := CreateConfig()
	cfg.ModSecurityUrl = "http://waf"
	cfg.DenyVerbsWithBody = []string{}
	if err := Prepare(cfg, "t"); err != nil {
		t.Fatal(err)
	}
	if cfg.DenyVerbsWithBody == nil || len(cfg.DenyVerbsWithBody) != 0 {
		t.Fatalf("empty denyVerbsWithBody = %v, want empty non-nil", cfg.DenyVerbsWithBody)
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
