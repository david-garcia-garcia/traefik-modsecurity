package modsecurity

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff"
)

// wafGateKey is the single admission key on the Plugin's Gate.
const wafGateKey = "waf"

// Plugin is the shared core for one middleware name+config: WAF client, logger, admission gate, and body buffer pool.
type Plugin struct {
	modSecurityUrl                 string
	name                           string
	httpClient                     *http.Client
	logger                         *slog.Logger
	wafGate                        *backendbackoff.Gate
	bodyBufferPool                 bufferPool
	modSecurityStatusRequestHeader string
	maxBodySizeBytes               int64
	maxBodySizeBytesForPool        int64
	denyVerbsWithBody              map[string]bool
	compiledBypass                 compiledBypass
	// failMode is the prepared failMode: open calls next on WAF communication failure; close writes empty HTTP 502.
	failMode string
}

// New builds the Plugin. cfg must already be Prepare'd. logger is the shared core logger.
func New(name string, cfg *Config, logger *slog.Logger) (*Plugin, error) {
	if err := Prepare(cfg, name); err != nil {
		return nil, err
	}
	if logger == nil {
		return nil, fmt.Errorf("%s: no logger provided", name)
	}

	timeout := 2 * time.Second
	if cfg.TimeoutMillis != 0 {
		timeout = time.Duration(cfg.TimeoutMillis) * time.Millisecond
	}

	// dialer is a custom net.Dialer with a specified timeout and keep-alive duration.
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// transport is a custom http.Transport with configurable timeouts and connection limits
	transport := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}

	if cfg.MaxConnsPerHost > 0 {
		transport.MaxConnsPerHost = cfg.MaxConnsPerHost
	}
	if cfg.MaxIdleConnsPerHost > 0 {
		transport.MaxIdleConnsPerHost = cfg.MaxIdleConnsPerHost
	}
	if cfg.ResponseHeaderTimeoutMillis > 0 {
		transport.ResponseHeaderTimeout = time.Duration(cfg.ResponseHeaderTimeoutMillis) * time.Millisecond
	}
	if cfg.ExpectContinueTimeoutMillis > 0 {
		transport.ExpectContinueTimeout = time.Duration(cfg.ExpectContinueTimeoutMillis) * time.Millisecond
	}

	wafGate, err := newWafGate(cfg)
	if err != nil {
		return nil, err
	}

	compiledBypass, err := compileBypassByMethod(cfg.BypassRules)
	if err != nil {
		return nil, err
	}

	return &Plugin{
		modSecurityUrl: cfg.ModSecurityUrl,
		name:           name,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			// Keep the sidecar's own 3xx so ServeHTTP can copy it; default follow hides redirect blocks.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		logger:                         logger,
		wafGate:                        wafGate,
		bodyBufferPool:                 newBodyBufferPool(),
		modSecurityStatusRequestHeader: cfg.ModSecurityStatusRequestHeader,
		maxBodySizeBytes:               cfg.MaxBodySizeBytes,
		maxBodySizeBytesForPool:        cfg.MaxBodySizeBytesForPool,
		denyVerbsWithBody:              createMethodSet(cfg.DenyVerbsWithBody),
		compiledBypass:                 compiledBypass,
		failMode:                       cfg.FailMode,
	}, nil
}

// NewLogger builds the plugin-owned slog logger for prepared cfg. Writes text to process stdout.
// name is attached so request, health, and reclaim lines can be joined when several middlewares share stdout.
func NewLogger(name string, cfg *Config) *slog.Logger {
	level := slog.LevelInfo
	if parsed, err := parseLogLevel(cfg.LogLevel); err == nil {
		level = parsed
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})).With("middleware", name)
}

// Close releases the WAF admission gate and idle HTTP connections when the reclaim incarnation ends.
func (p *Plugin) Close() {
	if p == nil {
		return
	}
	if p.wafGate != nil {
		p.wafGate.Close()
	}
	if p.httpClient != nil {
		p.httpClient.CloseIdleConnections()
	}
}

// HTTPClient is the shared WAF client. Tests compare identity across New calls.
func (p *Plugin) HTTPClient() *http.Client {
	if p == nil {
		return nil
	}
	return p.httpClient
}

// newWafGate builds the upstream admission gate when backoff seconds are greater than zero.
func newWafGate(cfg *Config) (*backendbackoff.Gate, error) {
	if cfg.UnhealthyWafBackOffPeriodSecs <= 0 {
		return nil, nil
	}
	base := time.Duration(cfg.UnhealthyWafBackOffPeriodSecs) * time.Second
	maxCooldown := base
	if cfg.UnhealthyWafMaxBackOffPeriodSecs > 0 {
		maxCooldown = time.Duration(cfg.UnhealthyWafMaxBackOffPeriodSecs) * time.Second
	}
	gateCfg := backendbackoff.Config{
		TripFailures: cfg.UnhealthyWafFailureThreshold,
		BaseCooldown: base,
		MaxCooldown:  maxCooldown,
	}
	if cfg.UnhealthyWafFailureRatio > 0 {
		gateCfg.FailureRatio = cfg.UnhealthyWafFailureRatio
	}
	gate, err := backendbackoff.New(gateCfg)
	if err != nil {
		return nil, fmt.Errorf("waf admission gate: %w", err)
	}
	return gate, nil
}

// createMethodSet converts HTTP methods to an uppercase set for O(1) lookup.
func createMethodSet(methods []string) map[string]bool {
	set := make(map[string]bool, len(methods))
	for _, method := range methods {
		set[strings.ToUpper(method)] = true
	}
	return set
}
