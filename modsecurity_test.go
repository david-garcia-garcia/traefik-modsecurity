package traefik_modsecurity_plugin

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
		name            string
		request         *http.Request
		wafResponse     response
		serviceResponse response
		expectBody      string
		expectStatus    int
	}{
		{
			name:    "Forward request when WAF found no threats",
			request: req.Clone(req.Context()),
			wafResponse: response{
				StatusCode: 200,
				Body:       "Response from waf",
			},
			serviceResponse: serviceResponse,
			expectBody:      "Response from service",
			expectStatus:    200,
		},
		{
			name:    "Intercepts request when WAF found threats",
			request: req.Clone(req.Context()),
			wafResponse: response{
				StatusCode: 403,
				Body:       "Response from waf",
			},
			serviceResponse: serviceResponse,
			expectBody:      "Response from waf",
			expectStatus:    403,
		},
		{
			name: "Does not forward Websockets",
			request: &http.Request{
				Body: http.NoBody,
				Header: http.Header{
					"Upgrade": []string{"websocket"},
				},
				Method: http.MethodGet,
				URL:    req.URL,
			},
			wafResponse: response{
				StatusCode: 200,
				Body:       "Response from waf",
			},
			serviceResponse: serviceResponse,
			expectBody:      "Response from service",
			expectStatus:    200,
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

			httpServiceHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp := http.Response{
					Body:       io.NopCloser(bytes.NewReader([]byte(tt.serviceResponse.Body))),
					StatusCode: tt.serviceResponse.StatusCode,
					Header:     http.Header{},
				}
				log.Printf("Service Handler: status code: %d, body: %s", resp.StatusCode, tt.serviceResponse.Body)
				forwardResponse(&resp, w)
			})

			config := &Config{
				TimeoutMillis:  2000,
				ModSecurityUrl: modsecurityMockServer.URL,
			}

			middleware, err := New(context.Background(), httpServiceHandler, config, "modsecurity-middleware")
			if err != nil {
				t.Fatalf("Failed to create middleware: %v", err)
			}

			rw := httptest.NewRecorder()
			middleware.ServeHTTP(rw, tt.request.Clone(tt.request.Context()))
			resp := rw.Result()
			body, _ := io.ReadAll(resp.Body)
			assert.Equal(t, tt.expectBody, string(body))
			assert.Equal(t, tt.expectStatus, resp.StatusCode)
		})
	}
}
