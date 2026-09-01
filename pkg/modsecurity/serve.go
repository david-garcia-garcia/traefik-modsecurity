package modsecurity

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// bodyBufferPool reuses buffers for request bodies under the pool threshold.
var bodyBufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// ServeHTTP proxies req to ModSecurity, then either blocks or calls next.
func (p *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request, next http.Handler) {
	if isWebsocket(req) {
		next.ServeHTTP(rw, req)
		return
	}

	// If the WAF is unhealthy just forward the request early.
	if p.healthTracker != nil && p.healthTracker.IsUnhealthy() {
		if p.modSecurityStatusRequestHeader != "" {
			req.Header.Set(p.modSecurityStatusRequestHeader, "unhealthy")
		}
		next.ServeHTTP(rw, req)
		return
	}

	// Check if we should enforce strict body validation for this HTTP method
	if p.ignoreBodyForVerbsDeny && p.ignoreBodyForVerbs[req.Method] {
		limitedBody := http.MaxBytesReader(rw, req.Body, 1)
		testByte := make([]byte, 1)
		if n, err := limitedBody.Read(testByte); n > 0 || err == nil {
			p.logger.Error("HTTP request should not have a body, rejecting", "method", req.Method)
			http.Error(rw, "HTTP "+req.Method+" requests should not have a body", http.StatusBadRequest)
			return
		}
	}

	// Read the body when this method is not on the ignore list.
	var body []byte
	if !p.ignoreBodyForVerbs[req.Method] {
		if p.maxBodySizeBytes > 0 {
			req.Body = http.MaxBytesReader(rw, req.Body, p.maxBodySizeBytes)
		}

		contentLengthStr := req.Header.Get("Content-Length")
		usePool := true
		if contentLengthStr != "" {
			if contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64); err == nil {
				usePool = contentLength <= p.maxBodySizeBytesForPool
			}
		}

		if usePool {
			buf := bodyBufferPool.Get().(*bytes.Buffer)
			buf.Reset()
			defer bodyBufferPool.Put(buf)

			if _, err := io.Copy(buf, req.Body); err != nil {
				if maxBytesErr, ok := err.(*http.MaxBytesError); ok {
					p.logger.Error("request body too large", "limit", maxBytesErr.Limit, "maxBodySizeBytes", p.maxBodySizeBytes)
					if p.modSecurityStatusRequestHeader != "" {
						req.Header.Set(p.modSecurityStatusRequestHeader, "blocked")
					}
					http.Error(rw, "Request body too large", http.StatusRequestEntityTooLarge)
					return
				}
				p.logger.Error("fail to read incoming request", "error", err)
				http.Error(rw, "", http.StatusBadGateway)
				return
			}
			body = buf.Bytes()
		} else {
			largeBody, err := io.ReadAll(req.Body)
			if err != nil {
				if maxBytesErr, ok := err.(*http.MaxBytesError); ok {
					p.logger.Error("request body too large", "limit", maxBytesErr.Limit, "maxBodySizeBytes", p.maxBodySizeBytes)
					if p.modSecurityStatusRequestHeader != "" {
						req.Header.Set(p.modSecurityStatusRequestHeader, "blocked")
					}
					http.Error(rw, "Request body too large", http.StatusRequestEntityTooLarge)
					return
				}
				p.logger.Error("fail to read incoming request", "error", err)
				http.Error(rw, "", http.StatusBadGateway)
				return
			}
			body = largeBody
		}
	}

	// Build the WAF request and send it on the shared client.
	url := p.modSecurityUrl + req.URL.RequestURI()

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	proxyReq, err := http.NewRequest(req.Method, url, bodyReader)
	if err != nil {
		if p.modSecurityStatusRequestHeader != "" {
			req.Header.Set(p.modSecurityStatusRequestHeader, "cannotforward")
		}
		p.logger.Error("fail to prepare forwarded request", "error", err)
		http.Error(rw, "", http.StatusBadGateway)
		return
	}

	proxyReq.Header = make(http.Header, len(req.Header))
	for h, val := range req.Header {
		proxyReq.Header[h] = val
	}

	resp, err := p.httpClient.Do(proxyReq)
	if err != nil {
		p.failWafRequest(rw, req, next, body, err)
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			p.logger.Error("fail to close WAF response body", "error", err)
		}
	}()

	// Sidecar 5xx is a WAF failure, not a security block.
	if resp.StatusCode >= 500 {
		if p.modSecurityStatusRequestHeader != "" {
			req.Header.Set(p.modSecurityStatusRequestHeader, "error")
		}
		p.failWafRequest(rw, req, next, body, fmt.Errorf("waf status %d", resp.StatusCode))
		return
	}

	// Block: copy the WAF 4xx response and do not call next.
	if resp.StatusCode >= 400 {
		if p.modSecurityStatusRequestHeader != "" {
			req.Header.Set(p.modSecurityStatusRequestHeader, "blocked")
		}
		forwardResponse(resp, rw)
		return
	}

	// Pass: restore the body Traefik still needs for the backend.
	if body != nil {
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	next.ServeHTTP(rw, req)
}

// failWafRequest records a WAF communication failure and fail-opens or returns 502.
func (p *Plugin) failWafRequest(rw http.ResponseWriter, req *http.Request, next http.Handler, body []byte, cause error) {
	// Record the failure; pass through when the shared tracker trips.
	if p.healthTracker != nil {
		if becameUnhealthy := p.healthTracker.RecordFailure(); becameUnhealthy && p.modSecurityStatusRequestHeader != "" {
			req.Header.Set(p.modSecurityStatusRequestHeader, "error")
		}
		if p.healthTracker.IsUnhealthy() {
			if body != nil {
				req.Body = io.NopCloser(bytes.NewReader(body))
			}
			next.ServeHTTP(rw, req)
			return
		}
	}

	p.logger.Error("fail to send HTTP request to modsec", "error", cause)
	http.Error(rw, "", http.StatusBadGateway)
}

// isWebsocket reports whether req is an HTTP/1.1 WebSocket handshake.
func isWebsocket(req *http.Request) bool {
	if req.Method != http.MethodGet {
		return false
	}
	if !headerValuesContainToken(req.Header.Values("Connection"), "upgrade") {
		return false
	}
	for _, value := range req.Header.Values("Upgrade") {
		if strings.EqualFold(value, "websocket") {
			return true
		}
	}
	return false
}

// headerValuesContainToken reports whether any comma-separated token in values equals token, ignoring ASCII case.
func headerValuesContainToken(values []string, token string) bool {
	// Connection and similar fields are comma-separated token lists.
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// forwardResponse copies the WAF response to the client.
func forwardResponse(resp *http.Response, rw http.ResponseWriter) {
	dst := rw.Header()
	for k, vv := range resp.Header {
		dst[k] = append(dst[k][:0], vv...)
	}
	rw.WriteHeader(resp.StatusCode)
	// Headers are already sent; a copy failure cannot change the status.
	if _, err := io.Copy(rw, resp.Body); err != nil {
		return
	}
}
