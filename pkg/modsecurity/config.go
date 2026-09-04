package modsecurity

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"
)

// Accepted logLevel strings after Prepare. Stored lowercase.
const (
	LogLevelDebug = "debug"
	LogLevelInfo  = "info"
	LogLevelWarn  = "warn"
	LogLevelError = "error"
)

// BypassRule is one operator allowlist entry: optional method and optional path regexp.
// Empty method matches every method. Empty pathRegexp matches every path.
// PathRegexp is Go RE2, matched with unanchored MatchString against req.URL.Path
// (percent-decoded, not slash-normalized). The plugin does not insert ^ or $.
// Write ^/health$ for an exact path, ^/admin/ for a prefix.
type BypassRule struct {
	Method     string `json:"method,omitempty"`
	PathRegexp string `json:"pathRegexp,omitempty"`
}

// Config is the Traefik plugin configuration Yaegi decodes.
type Config struct {
	TimeoutMillis                  int64        `json:"timeoutMillis,omitempty"`
	ModSecurityUrl                 string       `json:"modSecurityUrl,omitempty"`
	UnhealthyWafBackOffPeriodSecs  int          `json:"unhealthyWafBackOffPeriodSecs,omitempty"`
	UnhealthyWafFailureThreshold   int          `json:"unhealthyWafFailureThreshold,omitempty"`
	UnhealthyWafFailureWindowSecs  int          `json:"unhealthyWafFailureWindowSecs,omitempty"`
	ModSecurityStatusRequestHeader string       `json:"modSecurityStatusRequestHeader,omitempty"`
	MaxConnsPerHost                int          `json:"maxConnsPerHost,omitempty"`
	MaxIdleConnsPerHost            int          `json:"maxIdleConnsPerHost,omitempty"`
	ResponseHeaderTimeoutMillis    int64        `json:"responseHeaderTimeoutMillis,omitempty"`
	ExpectContinueTimeoutMillis    int64        `json:"expectContinueTimeoutMillis,omitempty"`
	MaxBodySizeBytes               int64        `json:"maxBodySizeBytes,omitempty"`
	MaxBodySizeBytesForPool        int64        `json:"maxBodySizeBytesForPool,omitempty"`
	DenyVerbsWithBody              []string     `json:"denyVerbsWithBody,omitempty"`
	LogLevel                       string       `json:"logLevel,omitempty"`
	BypassRules                    []BypassRule `json:"bypassRules,omitempty"`
	FailClosed                     bool         `json:"failClosed,omitempty"`
}

// CreateConfig returns default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		TimeoutMillis:                  2000,
		UnhealthyWafBackOffPeriodSecs:  0,
		UnhealthyWafFailureThreshold:   5,
		UnhealthyWafFailureWindowSecs:  10,
		ModSecurityStatusRequestHeader: "",
		MaxConnsPerHost:                100,
		MaxIdleConnsPerHost:            10,
		ResponseHeaderTimeoutMillis:    0,
		ExpectContinueTimeoutMillis:    1000,
		MaxBodySizeBytes:               8 * 1024 * 1024,
		MaxBodySizeBytesForPool:        5 * 1024 * 1024,
		DenyVerbsWithBody:              []string{"HEAD", "GET", "DELETE", "OPTIONS", "TRACE", "CONNECT"},
		LogLevel:                       LogLevelInfo,
	}
}

// Prepare validates cfg and fills CreateConfig defaults for omitted zeros so the reclaim hash is stable.
func Prepare(cfg *Config, name string) error {
	if cfg == nil {
		return fmt.Errorf("%s: no config provided", name)
	}
	if len(cfg.ModSecurityUrl) == 0 {
		return fmt.Errorf("modSecurityUrl cannot be empty")
	}
	defaults := CreateConfig()
	if cfg.TimeoutMillis == 0 {
		cfg.TimeoutMillis = defaults.TimeoutMillis
	}
	if cfg.UnhealthyWafFailureThreshold == 0 {
		cfg.UnhealthyWafFailureThreshold = defaults.UnhealthyWafFailureThreshold
	}
	if cfg.UnhealthyWafFailureWindowSecs == 0 {
		cfg.UnhealthyWafFailureWindowSecs = defaults.UnhealthyWafFailureWindowSecs
	}
	if cfg.MaxConnsPerHost == 0 {
		cfg.MaxConnsPerHost = defaults.MaxConnsPerHost
	}
	if cfg.MaxIdleConnsPerHost == 0 {
		cfg.MaxIdleConnsPerHost = defaults.MaxIdleConnsPerHost
	}
	if cfg.ExpectContinueTimeoutMillis == 0 {
		cfg.ExpectContinueTimeoutMillis = defaults.ExpectContinueTimeoutMillis
	}
	if cfg.MaxBodySizeBytes == 0 {
		cfg.MaxBodySizeBytes = defaults.MaxBodySizeBytes
	}
	if cfg.MaxBodySizeBytesForPool == 0 {
		cfg.MaxBodySizeBytesForPool = defaults.MaxBodySizeBytesForPool
	}
	// Nil means omitted (use default). Explicit empty means deny nothing.
	if cfg.DenyVerbsWithBody == nil {
		cfg.DenyVerbsWithBody = defaults.DenyVerbsWithBody
	}
	// Reject negatives so a typo cannot drop a limit or disable a timeout.
	if err := rejectNegative("timeoutMillis", cfg.TimeoutMillis); err != nil {
		return err
	}
	if err := rejectNegative("unhealthyWafBackOffPeriodSecs", int64(cfg.UnhealthyWafBackOffPeriodSecs)); err != nil {
		return err
	}
	if err := rejectNegative("unhealthyWafFailureThreshold", int64(cfg.UnhealthyWafFailureThreshold)); err != nil {
		return err
	}
	if err := rejectNegative("unhealthyWafFailureWindowSecs", int64(cfg.UnhealthyWafFailureWindowSecs)); err != nil {
		return err
	}
	if err := rejectNegative("maxConnsPerHost", int64(cfg.MaxConnsPerHost)); err != nil {
		return err
	}
	if err := rejectNegative("maxIdleConnsPerHost", int64(cfg.MaxIdleConnsPerHost)); err != nil {
		return err
	}
	if err := rejectNegative("responseHeaderTimeoutMillis", cfg.ResponseHeaderTimeoutMillis); err != nil {
		return err
	}
	if err := rejectNegative("expectContinueTimeoutMillis", cfg.ExpectContinueTimeoutMillis); err != nil {
		return err
	}
	if err := rejectNegative("maxBodySizeBytes", cfg.MaxBodySizeBytes); err != nil {
		return err
	}
	if err := rejectNegative("maxBodySizeBytesForPool", cfg.MaxBodySizeBytesForPool); err != nil {
		return err
	}
	// Parse the WAF base so ServeHTTP concatenation cannot start from a typo or a trailing slash.
	preparedURL, err := prepareModSecurityURL(cfg.ModSecurityUrl)
	if err != nil {
		return err
	}
	cfg.ModSecurityUrl = preparedURL
	// Normalize logLevel so the reclaim hash is stable across case and omitted values.
	normalizedLevel := strings.ToLower(strings.TrimSpace(cfg.LogLevel))
	if normalizedLevel == "" {
		normalizedLevel = defaults.LogLevel
	}
	if _, err := parseLogLevel(normalizedLevel); err != nil {
		return err
	}
	cfg.LogLevel = normalizedLevel
	// Fail construction on a bad pathRegexp before New stores a compiled map.
	if _, err := compileBypassByMethod(cfg.BypassRules); err != nil {
		return err
	}
	return nil
}

// rejectNegative returns an error when value is less than zero.
func rejectNegative(field string, value int64) error {
	if value < 0 {
		return fmt.Errorf("%s must not be negative", field)
	}
	return nil
}

// prepareModSecurityURL parses raw as an absolute http/https WAF base with a host and no path.
func prepareModSecurityURL(raw string) (string, error) {
	// Parse first; a hostname with no scheme may not error, so the field checks below still run.
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("modSecurityUrl is not a valid URL: %w", err)
	}
	if !parsed.IsAbs() {
		return "", fmt.Errorf("modSecurityUrl must be an absolute http or https URL")
	}
	// Scheme and host are the only allowed authority; extra URL parts change sidecar paths or leak credentials.
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("modSecurityUrl must be an absolute http or https URL")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("modSecurityUrl must include a host")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("modSecurityUrl must not include userinfo")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		return "", fmt.Errorf("modSecurityUrl must not include a query")
	}
	if parsed.Fragment != "" {
		return "", fmt.Errorf("modSecurityUrl must not include a fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("modSecurityUrl must not include a path")
	}
	return strings.TrimSuffix(raw, "/"), nil
}

// parseLogLevel maps a prepared logLevel string to slog. Empty is not accepted here; Prepare fills info first.
func parseLogLevel(level string) (slog.Level, error) {
	switch level {
	case LogLevelDebug:
		return slog.LevelDebug, nil
	case LogLevelInfo:
		return slog.LevelInfo, nil
	case LogLevelWarn:
		return slog.LevelWarn, nil
	case LogLevelError:
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("logLevel must be debug, info, warn, or error")
	}
}
