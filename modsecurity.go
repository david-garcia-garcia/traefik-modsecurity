// Package traefik_modsecurity a modsecurity plugin.
package traefik_modsecurity

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Buffer pool for body reading to reduce allocations
var bodyBufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// Config the plugin configuration.
type Config struct {
	TimeoutMillis                  int64    `json:"timeoutMillis,omitempty"`
	ModSecurityUrl                 string   `json:"modSecurityUrl,omitempty"`
	UnhealthyWafBackOffPeriodSecs  int      `json:"unhealthyWafBackOffPeriodSecs,omitempty"`  // If the WAF is unhealthy, back off
	ModSecurityStatusRequestHeader string   `json:"modSecurityStatusRequestHeader,omitempty"` // Header name to add to request when blocked (for logging)
	MaxConnsPerHost                int      `json:"maxConnsPerHost,omitempty"`                // Maximum connections per host (0 = unlimited, original default)
	MaxIdleConnsPerHost            int      `json:"maxIdleConnsPerHost,omitempty"`            // Maximum idle connections per host (0 = unlimited, original default)
	ResponseHeaderTimeoutMillis    int64    `json:"responseHeaderTimeoutMillis,omitempty"`    // Timeout for response headers (0 = no timeout, original default)
	ExpectContinueTimeoutMillis    int64    `json:"expectContinueTimeoutMillis,omitempty"`    // Timeout for Expect: 100-continue (default 1000ms)
	MaxBodySizeBytes               int64    `json:"maxBodySizeBytes,omitempty"`               // Maximum request body size in bytes (0 = unlimited, default 5MB)
	MaxBodySizeBytesForPool        int64    `json:"maxBodySizeBytesForPool,omitempty"`        // Threshold above which to use ad-hoc allocation instead of pool (default 4MB)
	IgnoreBodyForVerbs             []string `json:"ignoreBodyForVerbs,omitempty"`             // HTTP verbs for which body should not be read (default: HEAD, GET, DELETE)
	IgnoreBodyForVerbsDeny         bool     `json:"ignoreBodyForVerbsDeny,omitempty"`         // If true, reject requests with body for verbs in IgnoreBodyForVerbs
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		TimeoutMillis:                  2000,                                                             // Original default: 2 seconds
		UnhealthyWafBackOffPeriodSecs:  0,                                                                // 0 to NOT backoff (original behaviour)
		ModSecurityStatusRequestHeader: "",                                                               // Empty string means no header will be added
		MaxConnsPerHost:                100,                                                              // Limit concurrent connections per host (was 0 = unlimited)
		MaxIdleConnsPerHost:            10,                                                               // Limit idle connections per host (was 0 = unlimited)
		ResponseHeaderTimeoutMillis:    0,                                                                // 0 = no response header timeout (original default)
		ExpectContinueTimeoutMillis:    1000,                                                             // 1 second (original default)
		MaxBodySizeBytes:               8 * 1024 * 1024,                                                  // 8 MB default
		MaxBodySizeBytesForPool:        5 * 1024 * 1024,                                                  // 5 MB default for pool threshold
		IgnoreBodyForVerbs:             []string{"HEAD", "GET", "DELETE", "OPTIONS", "TRACE", "CONNECT"}, // Default verbs to ignore body
		IgnoreBodyForVerbsDeny:         false,                                                            // Default: permissive body validation
	}
}

// Modsecurity a Modsecurity plugin.
type Modsecurity struct {
	next                           http.Handler
	modSecurityUrl                 string
	name                           string
	httpClient                     *http.Client
	logger                         *log.Logger
	unhealthyWafBackOffPeriodSecs  int
	unhealthyWaf                   bool // If the WAF is unhealthy
	unhealthyWafMutex              sync.Mutex
	modSecurityStatusRequestHeader string          // Header name to add to request when blocked (for logging)
	maxBodySizeBytes               int64           // Maximum request body size in bytes
	maxBodySizeBytesForPool        int64           // Threshold above which to use ad-hoc allocation instead of pool
	ignoreBodyForVerbs             map[string]bool // HTTP verbs for which body should not be read
	ignoreBodyForVerbsDeny         bool            // If true, reject requests with body for verbs in ignoreBodyForVerbs
}

// New creates a new Modsecurity plugin with the given configuration.
// It returns an HTTP handler that can be integrated into the Traefik middleware chain.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.ModSecurityUrl) == 0 {
		return nil, fmt.Errorf("modSecurityUrl cannot be empty")
	}

	// Use a custom client with configurable timeout
	var timeout time.Duration
	if config.TimeoutMillis == 0 {
		timeout = 2 * time.Second // Original default: 2 seconds
	} else {
		timeout = time.Duration(config.TimeoutMillis) * time.Millisecond
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

	// Configure connection limits (0 = unlimited, original behavior)
	if config.MaxConnsPerHost > 0 {
		transport.MaxConnsPerHost = config.MaxConnsPerHost
	}
	if config.MaxIdleConnsPerHost > 0 {
		transport.MaxIdleConnsPerHost = config.MaxIdleConnsPerHost
	}

	// Configure response header timeout (0 = no timeout, original behavior)
	if config.ResponseHeaderTimeoutMillis > 0 {
		transport.ResponseHeaderTimeout = time.Duration(config.ResponseHeaderTimeoutMillis) * time.Millisecond
	}

	// Configure Expect: 100-continue timeout
	if config.ExpectContinueTimeoutMillis > 0 {
		transport.ExpectContinueTimeout = time.Duration(config.ExpectContinueTimeoutMillis) * time.Millisecond
	}

	return &Modsecurity{
		modSecurityUrl:                 config.ModSecurityUrl,
		next:                           next,
		name:                           name,
		httpClient:                     &http.Client{Timeout: timeout, Transport: transport},
		logger:                         log.New(os.Stdout, "", log.LstdFlags),
		unhealthyWafBackOffPeriodSecs:  config.UnhealthyWafBackOffPeriodSecs,
		modSecurityStatusRequestHeader: config.ModSecurityStatusRequestHeader,
		maxBodySizeBytes:               config.MaxBodySizeBytes,
		maxBodySizeBytesForPool:        config.MaxBodySizeBytesForPool,
		ignoreBodyForVerbs:             createIgnoreBodyMap(config.IgnoreBodyForVerbs),
		ignoreBodyForVerbsDeny:         config.IgnoreBodyForVerbsDeny,
	}, nil
}

// createIgnoreBodyMap converts a slice of verbs to a map for O(1) lookup
func createIgnoreBodyMap(verbs []string) map[string]bool {
	ignoreMap := make(map[string]bool, len(verbs))
	for _, verb := range verbs {
		ignoreMap[strings.ToUpper(verb)] = true
	}
	return ignoreMap
}

func (a *Modsecurity) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if isWebsocket(req) {
		a.next.ServeHTTP(rw, req)
		return
	}

	// If the WAF is unhealthy just forward the request early. No concurrency control here on purpose.
	if a.unhealthyWaf {
		if a.modSecurityStatusRequestHeader != "" {
			req.Header.Set(a.modSecurityStatusRequestHeader, "unhealthy")
		}
		a.next.ServeHTTP(rw, req)
		return
	}

	// Check if we should enforce strict body validation for this HTTP method
	if a.ignoreBodyForVerbsDeny && a.ignoreBodyForVerbs[req.Method] {
		// Check if request has a body by trying to read 1 byte
		limitedBody := http.MaxBytesReader(rw, req.Body, 1)
		testByte := make([]byte, 1)
		if n, err := limitedBody.Read(testByte); n > 0 || err == nil {
			// Request has a body, but this method should not have one
			a.logger.Printf("HTTP %s request should not have a body, rejecting", req.Method)
			http.Error(rw, fmt.Sprintf("HTTP %s requests should not have a body", req.Method), http.StatusBadRequest)
			return
		}
		// No body detected, continue processing
	}

	// Check if we should skip body reading for this HTTP method
	var body []byte
	if !a.ignoreBodyForVerbs[req.Method] {
		// Limit body size if configured (security optimization)
		if a.maxBodySizeBytes > 0 {
			req.Body = http.MaxBytesReader(rw, req.Body, a.maxBodySizeBytes)
		}

		// Check Content-Length to decide whether to use pool or ad-hoc allocation
		contentLengthStr := req.Header.Get("Content-Length")
		usePool := true
		if contentLengthStr != "" {
			if contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64); err == nil {
				usePool = contentLength <= a.maxBodySizeBytesForPool
			}
		}

		if usePool {
			// Use pooled buffer for smaller requests
			buf := bodyBufferPool.Get().(*bytes.Buffer)
			buf.Reset()
			defer bodyBufferPool.Put(buf)

			// Read body into pooled buffer
			if _, err := io.Copy(buf, req.Body); err != nil {
				// Check if this is a MaxBytesError (body too large)
				if maxBytesErr, ok := err.(*http.MaxBytesError); ok {
					a.logger.Printf("request body too large: %d bytes (limit: %d bytes)", maxBytesErr.Limit, a.maxBodySizeBytes)
					// Mark the request as blocked by the middleware itself (for access-log correlation)
					if a.modSecurityStatusRequestHeader != "" {
						req.Header.Set(a.modSecurityStatusRequestHeader, "blocked")
					}
					http.Error(rw, "Request body too large", http.StatusRequestEntityTooLarge) // 413
					return
				}
				a.logger.Printf("fail to read incoming request: %s", err.Error())
				http.Error(rw, "", http.StatusBadGateway)
				return
			}
			body = buf.Bytes()
		} else {
			// Use ad-hoc allocation for larger requests to avoid pool pollution.
			// We still need to keep the body in memory so that we can:
			// - send it to ModSecurity, and
			// - restore it for the downstream handler (Traefik backend),
			// otherwise Traefik will see a Content-Length with an empty body and return 500.
			largeBody, err := io.ReadAll(req.Body)
			if err != nil {
				// Check if this is a MaxBytesError (body too large)
				if maxBytesErr, ok := err.(*http.MaxBytesError); ok {
					a.logger.Printf("request body too large: %d bytes (limit: %d bytes)", maxBytesErr.Limit, a.maxBodySizeBytes)
					// Mark the request as blocked by the middleware itself (for access-log correlation)
					if a.modSecurityStatusRequestHeader != "" {
						req.Header.Set(a.modSecurityStatusRequestHeader, "blocked")
					}
					http.Error(rw, "Request body too large", http.StatusRequestEntityTooLarge) // 413
					return
				}
				a.logger.Printf("fail to read incoming request: %s", err.Error())
				http.Error(rw, "", http.StatusBadGateway)
				return
			}
			// For large requests, we keep the body as a separate slice (not in the shared pool)
			// to avoid polluting the buffer pool with very large allocations.
			body = largeBody
		}
		// Don't restore req.Body yet - only create reader when needed
	}

	url := a.modSecurityUrl + req.RequestURI

	// Create request body reader (nil for methods that ignore body)
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	proxyReq, err := http.NewRequest(req.Method, url, bodyReader)
	if err != nil {
		if a.modSecurityStatusRequestHeader != "" {
			req.Header.Set(a.modSecurityStatusRequestHeader, "cannotforward")
		}
		a.logger.Printf("fail to prepare forwarded request: %s", err.Error())
		http.Error(rw, "", http.StatusBadGateway)
		return
	}

	// We may want to filter some headers, otherwise we could just use a shallow copy
	proxyReq.Header = make(http.Header, len(req.Header))
	for h, val := range req.Header {
		proxyReq.Header[h] = val
	}

	resp, err := a.httpClient.Do(proxyReq)
	if err != nil {
		if a.unhealthyWafBackOffPeriodSecs > 0 {
			a.unhealthyWafMutex.Lock()
			if !a.unhealthyWaf {
				a.logger.Printf("marking modsec as unhealthy for %ds fail to send HTTP request to modsec: %s", a.unhealthyWafBackOffPeriodSecs, err.Error())
				a.unhealthyWaf = true
				if a.modSecurityStatusRequestHeader != "" {
					req.Header.Set(a.modSecurityStatusRequestHeader, "error")
				}
				time.AfterFunc(time.Duration(a.unhealthyWafBackOffPeriodSecs)*time.Second, func() {
					a.unhealthyWafMutex.Lock()
					defer a.unhealthyWafMutex.Unlock()
					a.unhealthyWaf = false
					a.logger.Printf("modsec unhealthy backoff expired")
				})
			}
			a.unhealthyWafMutex.Unlock()
			// Only restore req.Body when passing through and body was read
			if body != nil {
				req.Body = io.NopCloser(bytes.NewReader(body))
			}
			a.next.ServeHTTP(rw, req)
			return
		}

		a.logger.Printf("fail to send HTTP request to modsec: %s", err.Error())
		http.Error(rw, "", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		// Add remediation header to request if configured (for logging purposes)
		if a.modSecurityStatusRequestHeader != "" {
			req.Header.Set(a.modSecurityStatusRequestHeader, "blocked")
		}
		forwardResponse(resp, rw)
		return
	}

	// Only restore req.Body when actually passing through and body was read
	if body != nil {
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	a.next.ServeHTTP(rw, req)
}

func isWebsocket(req *http.Request) bool {
	for _, header := range req.Header["Upgrade"] {
		if header == "websocket" {
			return true
		}
	}
	return false
}

func forwardResponse(resp *http.Response, rw http.ResponseWriter) {
	dst := rw.Header()
	for k, vv := range resp.Header {
		dst[k] = append(dst[k][:0], vv...)
	}
	// Copy status
	rw.WriteHeader(resp.StatusCode)
	// Copy body
	io.Copy(rw, resp.Body)
}
