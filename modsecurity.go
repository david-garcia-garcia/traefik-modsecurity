// Package traefik_modsecurity_plugin a modsecurity plugin.
package traefik_modsecurity_plugin

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
	"sync"
	"time"
)

// Config the plugin configuration.
type Config struct {
	TimeoutMillis                 int64  `json:"timeoutMillis,omitempty"`
	ModSecurityUrl                string `json:"modSecurityUrl,omitempty"`
	UnhealthyWafBackOffPeriodSecs int    `json:"unhealthyWafBackOffPeriodSecs,omitempty"` // If the WAF is unhealthy, back off
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		TimeoutMillis:                 2000,
		UnhealthyWafBackOffPeriodSecs: 0, // 0 to NOT backoff (original behaviour)
	}
}

// Modsecurity a Modsecurity plugin.
type Modsecurity struct {
	next                          http.Handler
	modSecurityUrl                string
	name                          string
	httpClient                    *http.Client
	logger                        *log.Logger
	unhealthyWafBackOffPeriodSecs int
	unhealthyWaf                  bool // If the WAF is unhealthy
	unhealthyWafMutex             sync.Mutex
}

// New creates a new Modsecurity plugin with the given configuration.
// It returns an HTTP handler that can be integrated into the Traefik middleware chain.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.ModSecurityUrl) == 0 {
		return nil, fmt.Errorf("modSecurityUrl cannot be empty")
	}

	// Use a custom client with predefined timeout of 2 seconds
	var timeout time.Duration
	if config.TimeoutMillis == 0 {
		timeout = 2 * time.Second
	} else {
		timeout = time.Duration(config.TimeoutMillis) * time.Millisecond
	}

	// dialer is a custom net.Dialer with a specified timeout and keep-alive duration.
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// transport is a custom http.Transport with various timeouts and configurations for optimal performance.
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

	return &Modsecurity{
		modSecurityUrl:                config.ModSecurityUrl,
		next:                          next,
		name:                          name,
		httpClient:                    &http.Client{Timeout: timeout, Transport: transport},
		logger:                        log.New(os.Stdout, "", log.LstdFlags),
		unhealthyWafBackOffPeriodSecs: config.UnhealthyWafBackOffPeriodSecs,
	}, nil
}

func (a *Modsecurity) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if isWebsocket(req) {
		a.next.ServeHTTP(rw, req)
		return
	}

	// If the WAF is unhealthy just forward the request early. No concurrency control here on purpose.
	if a.unhealthyWaf {
		a.next.ServeHTTP(rw, req)
		return
	}

	// Buffer the body if we want to read it here and send it in the request.
	body, err := io.ReadAll(req.Body)
	if err != nil {
		a.logger.Printf("fail to read incoming request: %s", err.Error())
		http.Error(rw, "", http.StatusBadGateway)
		return
	}
	req.Body = io.NopCloser(bytes.NewReader(body))

	// Create a new URL from the raw RequestURI sent by the client
	url := fmt.Sprintf("%s%s", a.modSecurityUrl, req.RequestURI)

	proxyReq, err := http.NewRequest(req.Method, url, bytes.NewReader(body))
	if err != nil {
		a.logger.Printf("fail to prepare forwarded request: %s", err.Error())
		http.Error(rw, "", http.StatusBadGateway)
		return
	}

	// We may want to filter some headers, otherwise we could just use a shallow copy
	proxyReq.Header = make(http.Header)
	for h, val := range req.Header {
		proxyReq.Header[h] = val
	}

	resp, err := a.httpClient.Do(proxyReq)
	if err != nil {
		if a.unhealthyWafBackOffPeriodSecs > 0 {
			a.unhealthyWafMutex.Lock()
			if a.unhealthyWaf == false {
				a.logger.Printf("marking modsec as unhealthy for %ds fail to send HTTP request to modsec: %s", a.unhealthyWafBackOffPeriodSecs, err.Error())
				a.unhealthyWaf = true
				time.AfterFunc(time.Duration(a.unhealthyWafBackOffPeriodSecs)*time.Second, func() {
					a.unhealthyWafMutex.Lock()
					defer a.unhealthyWafMutex.Unlock()
					a.unhealthyWaf = false
					a.logger.Printf("modsec unhealthy backoff expired")
				})
			}
			a.unhealthyWafMutex.Unlock()
			a.next.ServeHTTP(rw, req)
			return
		}

		a.logger.Printf("fail to send HTTP request to modsec: %s", err.Error())
		http.Error(rw, "", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		forwardResponse(resp, rw)
		return
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
	// Copy headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			rw.Header().Add(k, v)
		}
	}
	// Copy status
	rw.WriteHeader(resp.StatusCode)
	// Copy body
	io.Copy(rw, resp.Body)
}
