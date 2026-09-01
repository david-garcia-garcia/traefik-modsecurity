package modsecurity

import "fmt"

// Config is the Traefik plugin configuration Yaegi decodes.
type Config struct {
	TimeoutMillis                  int64    `json:"timeoutMillis,omitempty"`
	ModSecurityUrl                 string   `json:"modSecurityUrl,omitempty"`
	UnhealthyWafBackOffPeriodSecs  int      `json:"unhealthyWafBackOffPeriodSecs,omitempty"`
	UnhealthyWafFailureThreshold   int      `json:"unhealthyWafFailureThreshold,omitempty"`
	UnhealthyWafFailureWindowSecs  int      `json:"unhealthyWafFailureWindowSecs,omitempty"`
	ModSecurityStatusRequestHeader string   `json:"modSecurityStatusRequestHeader,omitempty"`
	MaxConnsPerHost                int      `json:"maxConnsPerHost,omitempty"`
	MaxIdleConnsPerHost            int      `json:"maxIdleConnsPerHost,omitempty"`
	ResponseHeaderTimeoutMillis    int64    `json:"responseHeaderTimeoutMillis,omitempty"`
	ExpectContinueTimeoutMillis    int64    `json:"expectContinueTimeoutMillis,omitempty"`
	MaxBodySizeBytes               int64    `json:"maxBodySizeBytes,omitempty"`
	MaxBodySizeBytesForPool        int64    `json:"maxBodySizeBytesForPool,omitempty"`
	IgnoreBodyForVerbs             []string `json:"ignoreBodyForVerbs,omitempty"`
	IgnoreBodyForVerbsDeny         bool     `json:"ignoreBodyForVerbsDeny,omitempty"`
}

// CreateConfig returns default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		TimeoutMillis:                  2000,
		UnhealthyWafBackOffPeriodSecs:  0,
		UnhealthyWafFailureThreshold:   1,
		UnhealthyWafFailureWindowSecs:  0,
		ModSecurityStatusRequestHeader: "",
		MaxConnsPerHost:                100,
		MaxIdleConnsPerHost:            10,
		ResponseHeaderTimeoutMillis:    0,
		ExpectContinueTimeoutMillis:    1000,
		MaxBodySizeBytes:               8 * 1024 * 1024,
		MaxBodySizeBytesForPool:        5 * 1024 * 1024,
		IgnoreBodyForVerbs:             []string{"HEAD", "GET", "DELETE", "OPTIONS", "TRACE", "CONNECT"},
		IgnoreBodyForVerbsDeny:         false,
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
	if len(cfg.IgnoreBodyForVerbs) == 0 {
		cfg.IgnoreBodyForVerbs = defaults.IgnoreBodyForVerbs
	}
	return nil
}
