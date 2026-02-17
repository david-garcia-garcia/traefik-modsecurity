package traefik_modsecurity

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

// chunkedReader reads data in chunks to simulate real-world streaming
type chunkedReader struct {
	data   []byte
	pos    int
	chunkSize int
}

func newChunkedReader(data []byte, chunkSize int) *chunkedReader {
	return &chunkedReader{data: data, chunkSize: chunkSize}
}

func (r *chunkedReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	toRead := r.chunkSize
	if toRead > len(p) {
		toRead = len(p)
	}
	if r.pos+toRead > len(r.data) {
		toRead = len(r.data) - r.pos
	}
	copy(p, r.data[r.pos:r.pos+toRead])
	r.pos += toRead
	return toRead, nil
}

func (r *chunkedReader) Close() error {
	return nil
}

func TestModsecurity_ServeHTTP(t *testing.T) {

	req, err := http.NewRequest(http.MethodGet, "http://proxy.com/test", bytes.NewBuffer([]byte("Request")))

	if err != nil {
		log.Fatal(err)
	}

	type response struct {
		Body       string
		StatusCode int
	}

	serviceResponse := response{
		StatusCode: 200,
		Body:       "Response from service",
	}

	tests := []struct {
		name                           string
		request                        *http.Request
		wafResponse                    response
		serviceResponse                response
		expectBody                     string
		expectStatus                   int
		modSecurityStatusRequestHeader string
		expectHeader                   string
		expectHeaderValue              string
	}{
		{
			name:                           "Forward request when WAF found no threats",
			request:                        req.Clone(req.Context()),
			wafResponse:                    response{StatusCode: 200, Body: "Response from waf"},
			serviceResponse:                serviceResponse,
			expectBody:                     "Response from service",
			expectStatus:                   200,
			modSecurityStatusRequestHeader: "",
			expectHeader:                   "",
			expectHeaderValue:              "",
		},
		{
			name:                           "Intercepts request when WAF found threats",
			request:                        req.Clone(req.Context()),
			wafResponse:                    response{StatusCode: 403, Body: "Response from waf"},
			serviceResponse:                serviceResponse,
			expectBody:                     "Response from waf",
			expectStatus:                   403,
			modSecurityStatusRequestHeader: "",
			expectHeader:                   "",
			expectHeaderValue:              "",
		},
		{
			name: "Does not forward Websockets",
			request: &http.Request{
				Body:   http.NoBody,
				Header: http.Header{"Upgrade": []string{"websocket"}},
				Method: http.MethodGet,
				URL:    req.URL,
			},
			wafResponse:                    response{StatusCode: 200, Body: "Response from waf"},
			serviceResponse:                serviceResponse,
			expectBody:                     "Response from service",
			expectStatus:                   200,
			modSecurityStatusRequestHeader: "",
			expectHeader:                   "",
			expectHeaderValue:              "",
		},
		{
			name:                           "Adds remediation header when request is blocked",
			request:                        req,
			wafResponse:                    response{StatusCode: 403, Body: "Response from waf"},
			serviceResponse:                serviceResponse,
			expectBody:                     "Response from waf",
			expectStatus:                   403,
			modSecurityStatusRequestHeader: "X-Waf-Block",
			expectHeader:                   "X-Waf-Block",
			expectHeaderValue:              "blocked",
		},
		{
			name:                           "Does not add remediation header when request is allowed",
			request:                        req.Clone(req.Context()),
			wafResponse:                    response{StatusCode: 200, Body: "Response from waf"},
			serviceResponse:                serviceResponse,
			expectBody:                     "Response from service",
			expectStatus:                   200,
			modSecurityStatusRequestHeader: "X-Waf-Block",
			expectHeader:                   "",
			expectHeaderValue:              "",
		},
		{
			name:                           "Adds remediation header with different status codes",
			request:                        req,
			wafResponse:                    response{StatusCode: 406, Body: "Response from waf"},
			serviceResponse:                serviceResponse,
			expectBody:                     "Response from waf",
			expectStatus:                   406,
			modSecurityStatusRequestHeader: "X-Remediation-Info",
			expectHeader:                   "X-Remediation-Info",
			expectHeaderValue:              "blocked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modsecurityMockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp := http.Response{
					Body:       io.NopCloser(bytes.NewReader([]byte(tt.wafResponse.Body))),
					StatusCode: tt.wafResponse.StatusCode,
					Header:     http.Header{},
				}
				log.Printf("WAF Mock: status code: %d, body: %s", resp.StatusCode, tt.wafResponse.Body)
				forwardResponse(&resp, w)
			}))
			defer modsecurityMockServer.Close()

			var capturedRequest *http.Request
			httpServiceHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedRequest = r
				resp := http.Response{
					Body:       io.NopCloser(bytes.NewReader([]byte(tt.serviceResponse.Body))),
					StatusCode: tt.serviceResponse.StatusCode,
					Header:     http.Header{},
				}
				log.Printf("Service Handler: status code: %d, body: %s", resp.StatusCode, tt.serviceResponse.Body)
				forwardResponse(&resp, w)
			})

			config := &Config{
				TimeoutMillis:                  2000,
				ModSecurityUrl:                 modsecurityMockServer.URL,
				ModSecurityStatusRequestHeader: tt.modSecurityStatusRequestHeader,
			}

			middleware, err := New(context.Background(), httpServiceHandler, config, "modsecurity-middleware")
			if err != nil {
				t.Fatalf("Failed to create middleware: %v", err)
			}

			rw := httptest.NewRecorder()
			middleware.ServeHTTP(rw, tt.request)
			resp := rw.Result()
			body, _ := io.ReadAll(resp.Body)
			assert.Equal(t, tt.expectBody, string(body))
			assert.Equal(t, tt.expectStatus, resp.StatusCode)

			// Check for expected status header in request (not response)
			if tt.expectHeader != "" {
				// For blocked requests, the header is set on the request but the service handler is not called
				// So we need to check the original request that was passed to the middleware
				assert.Equal(t, tt.expectHeaderValue, tt.request.Header.Get(tt.expectHeader), "Expected status header in request with correct value")
			} else {
				// When no header is expected, ensure no status header was added to request
				if tt.modSecurityStatusRequestHeader != "" {
					if capturedRequest != nil {
						assert.Empty(t, capturedRequest.Header.Get(tt.modSecurityStatusRequestHeader), "No status header should be present in request")
					} else {
						// If service handler wasn't called (blocked request), check original request
						assert.Empty(t, tt.request.Header.Get(tt.modSecurityStatusRequestHeader), "No status header should be present in request")
					}
				}
			}
		})
	}
}

func TestModsecurity_BodySizeLimit_WhenNotUsingPool(t *testing.T) {
	// This test reproduces the bug where MaxBytesError is not properly detected
	// when usePool=false (i.e., when Content-Length > maxBodySizeBytesForPool)
	// 
	// The bug: When usePool=false, io.ReadAll may not properly detect MaxBytesError
	// and the request may pass through to the backend even when it exceeds the limit
	
	// Set a small pool threshold so we trigger the usePool=false path
	maxBodySizeBytesForPool := int64(1024) // 1KB - small threshold
	maxBodySizeBytes := int64(5 * 1024)    // 5KB - larger limit
	
	tests := []struct {
		name                string
		bodySize            int64  // Size of request body in bytes
		contentLength       string // Content-Length header value
		expectStatus        int
		expectBackendCalled bool
		description         string
	}{
		{
			name:                "Body within limit, triggers usePool=false path",
			bodySize:            2 * 1024, // 2KB - within 5KB limit but > 1KB pool threshold
			contentLength:       "2048",
			expectStatus:        200, // Should pass through
			expectBackendCalled: true,
			description:         "2KB body should pass (within 5KB limit, but > 1KB pool threshold)",
		},
		{
			name:                "Body exceeds limit, triggers usePool=false path - THIS SHOULD FAIL",
			bodySize:            6 * 1024, // 6KB - exceeds 5KB limit and > 1KB pool threshold
			contentLength:       "6144",
			expectStatus:        413, // Should be rejected
			expectBackendCalled: false, // Backend should NOT be called
			description:         "6KB body should be rejected (exceeds 5KB limit, triggers usePool=false) - REPRODUCES BUG",
		},
		{
			name:                "Body exactly at limit, triggers usePool=false path",
			bodySize:            5 * 1024, // 5KB - exactly at limit, > 1KB pool threshold
			contentLength:       "5120",
			expectStatus:        200, // Should pass (at limit, not exceeding)
			expectBackendCalled: true,
			description:         "5KB body should pass (exactly at limit, triggers usePool=false)",
		},
		{
			name:                "Body exceeds limit by 1 byte, triggers usePool=false path - THIS SHOULD FAIL",
			bodySize:            5*1024 + 1, // 5KB + 1 byte - exceeds limit by 1 byte
			contentLength:       "5121",
			expectStatus:        413, // Should be rejected
			expectBackendCalled: false, // Backend should NOT be called
			description:         "5KB+1 body should be rejected (exceeds limit by 1 byte) - REPRODUCES BUG",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock WAF server that always returns 200
			var wafBodyReceived []byte
			modsecurityMockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Read the body sent to WAF
				wafBodyReceived, _ = io.ReadAll(r.Body)
				w.WriteHeader(200)
				w.Write([]byte("WAF OK"))
			}))
			defer modsecurityMockServer.Close()

			// Track if backend handler was called and what body it received
			backendCalled := false
			var backendBodyReceived []byte
			httpServiceHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				backendCalled = true
				backendBodyReceived, _ = io.ReadAll(r.Body)
				w.WriteHeader(200)
				w.Write([]byte("Backend OK"))
			})

			// Create request with body
			bodyData := make([]byte, tt.bodySize)
			for i := range bodyData {
				bodyData[i] = 'a'
			}
			
			req, err := http.NewRequest(http.MethodPost, "http://proxy.com/test", bytes.NewReader(bodyData))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Content-Length", tt.contentLength)

			config := &Config{
				TimeoutMillis:                  2000,
				ModSecurityUrl:                 modsecurityMockServer.URL,
				MaxBodySizeBytes:               maxBodySizeBytes,
				MaxBodySizeBytesForPool:        maxBodySizeBytesForPool,
				ModSecurityStatusRequestHeader: "X-Waf-Status",
			}

			middleware, err := New(context.Background(), httpServiceHandler, config, "modsecurity-middleware")
			if err != nil {
				t.Fatalf("Failed to create middleware: %v", err)
			}

			rw := httptest.NewRecorder()
			middleware.ServeHTTP(rw, req)
			resp := rw.Result()
			
			// Verify status code
			if resp.StatusCode != tt.expectStatus {
				t.Errorf("Status code mismatch for %s. Expected %d, got %d", 
					tt.description, tt.expectStatus, resp.StatusCode)
			}
			
			// Verify backend was called or not called as expected
			if backendCalled != tt.expectBackendCalled {
				t.Errorf("Backend call expectation mismatch for %s. Expected called=%v, got called=%v. "+
					"This indicates the bug: request exceeded limit but backend was still called (or vice versa)", 
					tt.description, tt.expectBackendCalled, backendCalled)
			}
			
			// If request was rejected (413), verify error message
			if tt.expectStatus == 413 {
				body, _ := io.ReadAll(resp.Body)
				if !bytes.Contains(body, []byte("Request body too large")) {
					t.Errorf("Expected error message about body being too large, got: %s", string(body))
				}
			}
			
			// Debug output for failed tests
			if resp.StatusCode != tt.expectStatus || backendCalled != tt.expectBackendCalled {
				t.Logf("Debug: bodySize=%d, contentLength=%s, status=%d, backendCalled=%v, wafBodyLen=%d, backendBodyLen=%d",
					tt.bodySize, tt.contentLength, resp.StatusCode, backendCalled, len(wafBodyReceived), len(backendBodyReceived))
			}
		})
	}
}

func TestModsecurity_BodySizeLimit_WithoutContentLength(t *testing.T) {
	// Test case: What happens when Content-Length header is missing or incorrect?
	// This might trigger usePool=true even for large bodies, or cause other issues
	
	maxBodySizeBytesForPool := int64(1024) // 1KB - small threshold
	maxBodySizeBytes := int64(5 * 1024)    // 5KB - larger limit
	
	tests := []struct {
		name                string
		bodySize            int64
		contentLength       string // Empty string means header not set
		expectStatus        int
		expectBackendCalled bool
		description         string
	}{
		{
			name:                "Large body without Content-Length header - might trigger usePool=true incorrectly",
			bodySize:            6 * 1024, // 6KB - exceeds limit
			contentLength:       "", // No Content-Length header
			expectStatus:        413, // Should be rejected
			expectBackendCalled: false,
			description:         "6KB body without Content-Length should be rejected",
		},
		{
			name:                "Large body with incorrect Content-Length (smaller than actual)",
			bodySize:            6 * 1024, // 6KB actual body
			contentLength:       "2048",   // But Content-Length says 2KB
			expectStatus:        413, // Should be rejected when actual body exceeds limit
			expectBackendCalled: false,
			description:         "6KB body with incorrect Content-Length should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modsecurityMockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				w.Write([]byte("WAF OK"))
			}))
			defer modsecurityMockServer.Close()

			backendCalled := false
			httpServiceHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				backendCalled = true
				w.WriteHeader(200)
				w.Write([]byte("Backend OK"))
			})

			bodyData := make([]byte, tt.bodySize)
			for i := range bodyData {
				bodyData[i] = 'a'
			}
			
			req, err := http.NewRequest(http.MethodPost, "http://proxy.com/test", bytes.NewReader(bodyData))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			if tt.contentLength != "" {
				req.Header.Set("Content-Length", tt.contentLength)
			}

			config := &Config{
				TimeoutMillis:                  2000,
				ModSecurityUrl:                 modsecurityMockServer.URL,
				MaxBodySizeBytes:               maxBodySizeBytes,
				MaxBodySizeBytesForPool:        maxBodySizeBytesForPool,
				ModSecurityStatusRequestHeader: "X-Waf-Status",
			}

			middleware, err := New(context.Background(), httpServiceHandler, config, "modsecurity-middleware")
			if err != nil {
				t.Fatalf("Failed to create middleware: %v", err)
			}

			rw := httptest.NewRecorder()
			middleware.ServeHTTP(rw, req)
			resp := rw.Result()
			
			if resp.StatusCode != tt.expectStatus {
				t.Errorf("Status code mismatch: Expected %d, got %d. %s", 
					tt.expectStatus, resp.StatusCode, tt.description)
			}
			
			if backendCalled != tt.expectBackendCalled {
				t.Errorf("Backend call mismatch: Expected called=%v, got called=%v. %s. "+
					"This indicates a bug!", tt.expectBackendCalled, backendCalled, tt.description)
			}
		})
	}
}

// Test scenario matching the real-world case: 20MB limit, 16MB body (and an over-limit body)
// This ensures both the usePool=true and usePool=false paths behave correctly at large sizes.
func TestModsecurity_BodySizeLimit_20MB_LargeBodies(t *testing.T) {
	const (
		mb                 = 1024 * 1024
		maxBodySizeBytes   = int64(20 * mb) // 20MB limit
		poolThresholdBytes = int64(4 * mb)  // 4MB pool threshold so 16MB uses usePool=false
	)

	tests := []struct {
		name                string
		bodySize            int64
		expectStatus        int
		expectBackendCalled bool
	}{
		{
			name:                "16MB body within 20MB limit (should pass, usePool=false)",
			bodySize:            16 * mb,
			expectStatus:        200,
			expectBackendCalled: true,
		},
		{
			name:                "21MB body exceeding 20MB limit (should be rejected, usePool=false)",
			bodySize:            21 * mb,
			expectStatus:        http.StatusRequestEntityTooLarge,
			expectBackendCalled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WAF mock just returns 200; we are testing the plugin's own body limiting.
			modsecurityMockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Drain body to simulate real WAF behaviour.
				_, _ = io.Copy(io.Discard, r.Body)
				w.WriteHeader(200)
				_, _ = w.Write([]byte("WAF OK"))
			}))
			defer modsecurityMockServer.Close()

			backendCalled := false
			httpServiceHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				backendCalled = true
				// Don't actually read the 16–21MB again, just drain.
				_, _ = io.Copy(io.Discard, r.Body)
				w.WriteHeader(200)
				_, _ = w.Write([]byte("Backend OK"))
			})

			// Allocate body of the requested size.
			bodyData := make([]byte, tt.bodySize)
			for i := range bodyData {
				bodyData[i] = 'a'
			}

			req, err := http.NewRequest(http.MethodPost, "http://proxy.com/test", bytes.NewReader(bodyData))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Content-Length", strconv.FormatInt(tt.bodySize, 10))

			config := &Config{
				TimeoutMillis:           30_000,
				ModSecurityUrl:          modsecurityMockServer.URL,
				MaxBodySizeBytes:        maxBodySizeBytes,
				MaxBodySizeBytesForPool: poolThresholdBytes,
			}

			middleware, err := New(context.Background(), httpServiceHandler, config, "modsecurity-20mb-test")
			if err != nil {
				t.Fatalf("Failed to create middleware: %v", err)
			}

			rw := httptest.NewRecorder()
			middleware.ServeHTTP(rw, req)
			resp := rw.Result()

			if resp.StatusCode != tt.expectStatus {
				t.Fatalf("unexpected status code: got %d, want %d", resp.StatusCode, tt.expectStatus)
			}

			if backendCalled != tt.expectBackendCalled {
				t.Fatalf("backendCalled mismatch: got %v, want %v", backendCalled, tt.expectBackendCalled)
			}
		})
	}
}
