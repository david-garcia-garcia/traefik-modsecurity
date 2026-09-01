package modsecurity

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"sync"
)

// bodyBufferPool reuses buffers for request bodies under the pool threshold.
var bodyBufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// ServeHTTP proxies req to ModSecurity, then either blocks or calls next.
func (a *Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request, next http.Handler) {
	if isWebsocket(req) {
		next.ServeHTTP(rw, req)
		return
	}

	// If the WAF is unhealthy just forward the request early.
	if a.healthTracker != nil && a.healthTracker.IsUnhealthy() {
		if a.modSecurityStatusRequestHeader != "" {
			req.Header.Set(a.modSecurityStatusRequestHeader, "unhealthy")
		}
		next.ServeHTTP(rw, req)
		return
	}

	// Check if we should enforce strict body validation for this HTTP method
	if a.ignoreBodyForVerbsDeny && a.ignoreBodyForVerbs[req.Method] {
		limitedBody := http.MaxBytesReader(rw, req.Body, 1)
		testByte := make([]byte, 1)
		if n, err := limitedBody.Read(testByte); n > 0 || err == nil {
			a.logger.Printf("HTTP %s request should not have a body, rejecting", req.Method)
			http.Error(rw, "HTTP "+req.Method+" requests should not have a body", http.StatusBadRequest)
			return
		}
	}

	var body []byte
	if !a.ignoreBodyForVerbs[req.Method] {
		if a.maxBodySizeBytes > 0 {
			req.Body = http.MaxBytesReader(rw, req.Body, a.maxBodySizeBytes)
		}

		contentLengthStr := req.Header.Get("Content-Length")
		usePool := true
		if contentLengthStr != "" {
			if contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64); err == nil {
				usePool = contentLength <= a.maxBodySizeBytesForPool
			}
		}

		if usePool {
			buf := bodyBufferPool.Get().(*bytes.Buffer)
			buf.Reset()
			defer bodyBufferPool.Put(buf)

			if _, err := io.Copy(buf, req.Body); err != nil {
				if maxBytesErr, ok := err.(*http.MaxBytesError); ok {
					a.logger.Printf("request body too large: %d bytes (limit: %d bytes)", maxBytesErr.Limit, a.maxBodySizeBytes)
					if a.modSecurityStatusRequestHeader != "" {
						req.Header.Set(a.modSecurityStatusRequestHeader, "blocked")
					}
					http.Error(rw, "Request body too large", http.StatusRequestEntityTooLarge)
					return
				}
				a.logger.Printf("fail to read incoming request: %s", err.Error())
				http.Error(rw, "", http.StatusBadGateway)
				return
			}
			body = buf.Bytes()
		} else {
			largeBody, err := io.ReadAll(req.Body)
			if err != nil {
				if maxBytesErr, ok := err.(*http.MaxBytesError); ok {
					a.logger.Printf("request body too large: %d bytes (limit: %d bytes)", maxBytesErr.Limit, a.maxBodySizeBytes)
					if a.modSecurityStatusRequestHeader != "" {
						req.Header.Set(a.modSecurityStatusRequestHeader, "blocked")
					}
					http.Error(rw, "Request body too large", http.StatusRequestEntityTooLarge)
					return
				}
				a.logger.Printf("fail to read incoming request: %s", err.Error())
				http.Error(rw, "", http.StatusBadGateway)
				return
			}
			body = largeBody
		}
	}

	url := a.modSecurityUrl + req.URL.RequestURI()

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

	proxyReq.Header = make(http.Header, len(req.Header))
	for h, val := range req.Header {
		proxyReq.Header[h] = val
	}

	resp, err := a.httpClient.Do(proxyReq)
	if err != nil {
		if a.healthTracker != nil {
			if becameUnhealthy := a.healthTracker.RecordFailure(); becameUnhealthy && a.modSecurityStatusRequestHeader != "" {
				req.Header.Set(a.modSecurityStatusRequestHeader, "error")
			}
			if a.healthTracker.IsUnhealthy() {
				if body != nil {
					req.Body = io.NopCloser(bytes.NewReader(body))
				}
				next.ServeHTTP(rw, req)
				return
			}
		}

		a.logger.Printf("fail to send HTTP request to modsec: %s", err.Error())
		http.Error(rw, "", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		if a.modSecurityStatusRequestHeader != "" {
			req.Header.Set(a.modSecurityStatusRequestHeader, "blocked")
		}
		forwardResponse(resp, rw)
		return
	}

	if body != nil {
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	next.ServeHTTP(rw, req)
}

// isWebsocket reports whether req is a websocket upgrade.
func isWebsocket(req *http.Request) bool {
	for _, header := range req.Header["Upgrade"] {
		if header == "websocket" {
			return true
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
	io.Copy(rw, resp.Body)
}
