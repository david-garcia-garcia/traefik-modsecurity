package modsecurity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// sidecarBodyDrainLimit is how many unread sidecar response bytes we discard
// so http.Transport can return the TCP connection to the idle pool.
const sidecarBodyDrainLimit = 256 << 10

// ServeHTTP proxies req to ModSecurity, then either blocks or calls next.
func (p *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request, next http.Handler) {
	// Operator allowlist: skip sidecar, body buffer, and local verb-body reject.
	if p.compiledBypass.match(req) {
		if p.modSecurityStatusRequestHeader != "" {
			req.Header.Set(p.modSecurityStatusRequestHeader, bypassStatusToken)
		}
		next.ServeHTTP(rw, req)
		return
	}

	if isWebsocket(req) {
		next.ServeHTTP(rw, req)
		return
	}

	// Reject a body on methods listed in denyVerbsWithBody before any forward.
	if p.denyVerbsWithBody[req.Method] {
		limitedBody := http.MaxBytesReader(rw, req.Body, 1)
		testByte := make([]byte, 1)
		if n, err := limitedBody.Read(testByte); n > 0 || err == nil {
			p.logger.Warn("HTTP request should not have a body, rejecting", "method", req.Method)
			http.Error(rw, "HTTP "+req.Method+" requests should not have a body", http.StatusBadRequest)
			return
		}
	}

	// If the WAF is unhealthy just forward the request early.
	if p.healthTracker != nil && p.healthTracker.IsUnhealthy() {
		if p.modSecurityStatusRequestHeader != "" {
			req.Header.Set(p.modSecurityStatusRequestHeader, "unhealthy")
		}
		next.ServeHTTP(rw, req)
		return
	}

	// Read the inbound body for the sidecar and restore it for next.
	body, releasePooledBuffer, err := p.readInboundBody(rw, req)
	if releasePooledBuffer != nil {
		defer releasePooledBuffer()
	}
	if err != nil {
		p.replyInboundBodyReadFailure(rw, req, err)
		return
	}

	// Build the WAF request and send it on the shared client.
	url := p.modSecurityUrl + req.URL.RequestURI()

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
		// Traefik still needs this body for next (pass and fail-open). Sidecar got its own reader.
		req.Body = io.NopCloser(bytes.NewReader(body))
	}

	// Bind the sidecar request to the inbound context so a client disconnect cancels it.
	proxyReq, err := http.NewRequestWithContext(req.Context(), req.Method, url, bodyReader)
	if err != nil {
		if p.modSecurityStatusRequestHeader != "" {
			req.Header.Set(p.modSecurityStatusRequestHeader, "error")
		}
		p.logger.Error("fail to prepare forwarded request", "error", err)
		http.Error(rw, "", http.StatusBadGateway)
		return
	}

	proxyReq.Header = make(http.Header, len(req.Header))
	for h, val := range req.Header {
		proxyReq.Header[h] = val
	}
	// Incoming Host is on req.Host, not in the header map. Traefik already set X-Real-Ip / leftover XFF.
	proxyReq.Host = req.Host

	resp, err := p.httpClient.Do(proxyReq)
	if err != nil {
		inboundErr := req.Context().Err()
		// Client disconnect or Traefik cancel of this request. The client can do this; do not trip WAF health.
		if errors.Is(inboundErr, context.Canceled) {
			p.logger.Info("inbound request canceled; WAF call aborted", "error", err, "inbound", inboundErr)
			http.Error(rw, "", http.StatusBadGateway)
			return
		}
		p.recordWafFailureAndReplyToClient(rw, req, next, err)
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			p.logger.Error("fail to close WAF response body", "error", err)
		}
	}()

	// Security block (3xx redirect, 4xx deny): copy the sidecar page, then we are done.
	if resp.StatusCode >= 300 && resp.StatusCode < 500 {
		if p.modSecurityStatusRequestHeader != "" {
			req.Header.Set(p.modSecurityStatusRequestHeader, "blocked")
		}
		forwardResponse(resp, rw)
		discardSidecarBody(resp.Body)
		return
	}
	discardSidecarBody(resp.Body)

	// Sidecar 5xx is a WAF failure, not a security block.
	if resp.StatusCode >= 500 {
		p.recordWafFailureAndReplyToClient(rw, req, next, fmt.Errorf("waf status %d", resp.StatusCode))
		return
	}
	// Sidecar allow: mark ok for access logs, then Traefik continues.
	if p.modSecurityStatusRequestHeader != "" {
		req.Header.Set(p.modSecurityStatusRequestHeader, "ok")
	}
	next.ServeHTTP(rw, req)
}

// replyInboundBodyReadFailure writes 413 for MaxBytesError or 502 for any other inbound body read error.
func (p *Plugin) replyInboundBodyReadFailure(rw http.ResponseWriter, req *http.Request, err error) {
	if maxBytesErr, ok := err.(*http.MaxBytesError); ok {
		p.logger.Warn("request body too large", "limit", maxBytesErr.Limit, "maxBodySizeBytes", p.maxBodySizeBytes)
		if p.modSecurityStatusRequestHeader != "" {
			req.Header.Set(p.modSecurityStatusRequestHeader, "blocked")
		}
		http.Error(rw, "Request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	p.logger.Error("fail to read incoming request", "error", err)
	http.Error(rw, "", http.StatusBadGateway)
}

// recordWafFailureAndReplyToClient records a WAF communication failure and replies to the client (fail-open or 502).
func (p *Plugin) recordWafFailureAndReplyToClient(rw http.ResponseWriter, req *http.Request, next http.Handler, cause error) {
	// One write: every WAF failure is "error" (sidecar 5xx and transport).
	if p.modSecurityStatusRequestHeader != "" {
		req.Header.Set(p.modSecurityStatusRequestHeader, "error")
	}

	// Record the failure; pass through when the shared tracker trips.
	if p.healthTracker != nil {
		p.healthTracker.RecordFailure()
		if p.healthTracker.IsUnhealthy() {
			next.ServeHTTP(rw, req)
			return
		}
	}

	p.logger.Error("fail to send HTTP request to modsec", "error", cause, "inbound", req.Context().Err())
	http.Error(rw, "", http.StatusBadGateway)
}

// discardSidecarBody discards leftover sidecar response bytes up to sidecarBodyDrainLimit so Close can return the TCP connection to the pool.
func discardSidecarBody(body io.Reader) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, sidecarBodyDrainLimit))
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
