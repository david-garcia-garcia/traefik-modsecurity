package modsecurity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// sidecarBodyDrainLimit is how many unread sidecar response bytes we discard
// so http.Transport can return the TCP connection to the idle pool.
const sidecarBodyDrainLimit = 256 << 10

// ServeHTTP proxies req to ModSecurity, then either blocks or calls next.
func (p *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request, next http.Handler) {
	// Operator allowlist: skip sidecar, body buffer, and local verb-body reject.
	if p.compiledBypass.match(req) {
		p.AddModsecStatusHeader(req, bypassStatusToken)
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
		p.AddModsecStatusHeader(req, "unhealthy")
		next.ServeHTTP(rw, req)
		return
	}

	// Read the inbound body fully into memory for the sidecar and next.
	// body may alias a pooled buffer; when releasePooledBuffer is non-nil it must be
	// called exactly once after both body consumers finish (or immediately on read error).
	body, releasePooledBuffer, err := p.readInboundBody(rw, req)
	if err != nil {
		if releasePooledBuffer != nil {
			releasePooledBuffer()
		}
		p.replyInboundBodyReadFailure(rw, req, err)
		return
	}
	// Panic between a successful pooled read and closer setup would otherwise drop the buffer.
	// Gate + defer Closes also call this; sync.Once keeps Put single-shot.
	var releaseOnce sync.Once
	safeReleasePooledBuffer := func() {
		if releasePooledBuffer != nil {
			releaseOnce.Do(releasePooledBuffer)
		}
	}
	defer safeReleasePooledBuffer()

	var sidecarBodyReadCloser io.ReadCloser
	var requestBodyReadCloser io.ReadCloser
	switch {
	case releasePooledBuffer != nil:
		gate := newPooledBodyGate(safeReleasePooledBuffer, 2)
		sidecarBodyReadCloser = newDoneReadCloser(bytes.NewReader(body), gate.consumerDone)
		requestBodyReadCloser = newDoneReadCloser(bytes.NewReader(body), gate.consumerDone)
		req.Body = requestBodyReadCloser
	case len(body) > 0:
		// Non-pooled (large) body: owned slice, no gate/finalizer.
		sidecarBodyReadCloser = io.NopCloser(bytes.NewReader(body))
		requestBodyReadCloser = io.NopCloser(bytes.NewReader(body))
		req.Body = requestBodyReadCloser
	}
	// Idempotent; runs after next on allow/fail-open so req.Body stays readable through next.
	// Also covers custom RoundTrippers / short-circuit next that omit Close.
	defer closeInboundBodyConsumer(sidecarBodyReadCloser)
	defer closeInboundBodyConsumer(requestBodyReadCloser)

	// Bind the sidecar request to the inbound context so a client disconnect cancels it.
	url := p.modSecurityUrl + req.URL.RequestURI()
	proxyReq, err := http.NewRequestWithContext(req.Context(), req.Method, url, sidecarBodyReadCloser)
	if err != nil {
		p.AddModsecStatusHeader(req, "error")
		p.logger.Error("fail to prepare forwarded request", "error", err)
		http.Error(rw, "", http.StatusBadGateway)
		return
	}
	if body != nil {
		// ReadCloser body skips NewRequest's bytes.Reader ContentLength/GetBody detection.
		proxyReq.ContentLength = int64(len(body))
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
		p.recordWafFailure(req, err)
		next.ServeHTTP(rw, req)
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			p.logger.Error("fail to close WAF response body", "error", err)
		}
	}()

	// Security block (3xx redirect, 4xx deny): copy the sidecar page, then we are done.
	if resp.StatusCode >= 300 && resp.StatusCode < 500 {
		p.AddModsecStatusHeader(req, "blocked")
		forwardResponse(resp, rw)
		discardSidecarBody(resp.Body)
		return
	}
	discardSidecarBody(resp.Body)

	// Sidecar 5xx is a WAF failure, not a security block.
	if resp.StatusCode >= 500 {
		p.recordWafFailure(req, fmt.Errorf("waf status %d", resp.StatusCode))
		next.ServeHTTP(rw, req)
		return
	}
	// Sidecar allow: mark ok for access logs, then Traefik continues.
	p.AddModsecStatusHeader(req, "ok")
	next.ServeHTTP(rw, req)
}

// replyInboundBodyReadFailure writes 413 for MaxBytesError or 502 for any other inbound body read error.
func (p *Plugin) replyInboundBodyReadFailure(rw http.ResponseWriter, req *http.Request, err error) {
	if maxBytesErr, ok := err.(*http.MaxBytesError); ok {
		p.logger.Warn("request body too large", "limit", maxBytesErr.Limit, "maxBodySizeBytes", p.maxBodySizeBytes)
		p.AddModsecStatusHeader(req, "blocked")
		http.Error(rw, "Request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	p.logger.Error("fail to read incoming request", "error", err)
	http.Error(rw, "", http.StatusBadGateway)
}

// recordWafFailure records a WAF communication failure: status header, optional health tracker, and log.
// The caller must fail-open to next; a WAF failure is never HTTP 502 Bad Gateway.
func (p *Plugin) recordWafFailure(req *http.Request, cause error) {
	p.AddModsecStatusHeader(req, "error")

	if p.healthTracker != nil {
		p.healthTracker.RecordFailure()
	}

	p.logger.Error("fail to send HTTP request to modsec", "error", cause, "inbound", req.Context().Err())
}

// AddModsecStatusHeader sets the optional WAF status request header when configured.
func (p *Plugin) AddModsecStatusHeader(req *http.Request, value string) {
	if p.modSecurityStatusRequestHeader != "" {
		req.Header.Set(p.modSecurityStatusRequestHeader, value)
	}
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

// forwardResponse copies the WAF response to the client, omitting hop-by-hop headers and Server.
func forwardResponse(resp *http.Response, rw http.ResponseWriter) {
	dst := rw.Header()
	connectionValues := resp.Header.Values("Connection")
	for k, vv := range resp.Header {
		if omitSidecarResponseHeader(k, connectionValues) {
			continue
		}
		dst[k] = append(dst[k][:0], vv...)
	}
	rw.WriteHeader(resp.StatusCode)
	// Headers are already sent; a copy failure cannot change the status.
	if _, err := io.Copy(rw, resp.Body); err != nil {
		return
	}
}

// omitSidecarResponseHeader reports whether name must not be copied from the sidecar to the client.
func omitSidecarResponseHeader(name string, connectionValues []string) bool {
	if strings.EqualFold(name, "Server") {
		return true
	}
	switch http.CanonicalHeaderKey(name) {
	case "Connection", "Keep-Alive", "Transfer-Encoding", "Upgrade", "Te", "Trailer":
		return true
	}
	if strings.HasPrefix(strings.ToLower(name), "proxy-") {
		return true
	}
	return headerValuesContainToken(connectionValues, name)
}
