package modsecurity

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

// keepassWebDAVPutBytes is the Content-Length from acouvreur#14
// (PUT /webdav/folder/mydb.kdbx.tmp).
const keepassWebDAVPutBytes = 228565

// TestCreateConfig_PutIsNotDeniedAndKeepassSizeFitsDefaultCap locks the
// defaults that matter for issue 14: PUT is not denyVerbsWithBody, and
// 228565 is under the 8 MiB plugin cap (CRS-docker nofiles 128 KiB is
// sidecar config, not this field).
func TestCreateConfig_PutIsNotDeniedAndKeepassSizeFitsDefaultCap(t *testing.T) {
	cfg := CreateConfig()
	if slices.Contains(cfg.DenyVerbsWithBody, http.MethodPut) {
		t.Fatal("CreateConfig DenyVerbsWithBody includes PUT; KeePass WebDAV would 400 locally")
	}
	if cfg.MaxBodySizeBytes != 8*1024*1024 {
		t.Fatalf("MaxBodySizeBytes %d, want 8 MiB", cfg.MaxBodySizeBytes)
	}
	if keepassWebDAVPutBytes >= cfg.MaxBodySizeBytes {
		t.Fatalf("reporter PUT %d >= plugin cap %d", keepassWebDAVPutBytes, cfg.MaxBodySizeBytes)
	}
}

// TestPlugin_KeepassWebDAVPutIsForwardedAndSidecar4xxCopied reproduces
// issue 14 in this plugin: a ~223 KiB PUT is read, sent to the sidecar,
// and a sidecar 400/413 is copied as a block (not a local 413 or deny-verb 400).
func TestPlugin_KeepassWebDAVPutIsForwardedAndSidecar4xxCopied(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAB}, keepassWebDAVPutBytes)

	tests := []struct {
		name             string
		wafStatus        int
		wantClientStatus int
		wantNext         bool
	}{
		{
			name:             "sidecar allow",
			wafStatus:        http.StatusOK,
			wantClientStatus: http.StatusOK,
			wantNext:         true,
		},
		{
			name:             "sidecar 400 body-parse (old 200002)",
			wafStatus:        http.StatusBadRequest,
			wantClientStatus: http.StatusBadRequest,
		},
		{
			name:             "sidecar 413 nofiles/engine limit",
			wafStatus:        http.StatusRequestEntityTooLarge,
			wantClientStatus: http.StatusRequestEntityTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotMethod string
			var gotLen int
			waf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod = r.Method
				body, _ := io.ReadAll(r.Body)
				gotLen = len(body)
				w.WriteHeader(tt.wafStatus)
				if tt.wafStatus != http.StatusOK {
					_, _ = io.WriteString(w, "sidecar deny")
				}
			}))
			t.Cleanup(waf.Close)

			cfg := CreateConfig()
			cfg.ModSecurityUrl = waf.URL
			plugin, err := New("issue-14-"+tt.name, cfg, NewLogger("issue-14-"+tt.name, cfg))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(plugin.Close)

			var nextCalled bool
			var nextLen int
			route, err := plugin.ForRoute(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				body, _ := io.ReadAll(r.Body)
				nextLen = len(body)
				w.WriteHeader(http.StatusOK)
			}))
			if err != nil {
				t.Fatalf("ForRoute: %v", err)
			}

			req := httptest.NewRequest(http.MethodPut, "http://webdav.example/folder/mydb.kdbx.tmp", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/octet-stream")
			req.Header.Set("Expect", "100-continue")
			rec := httptest.NewRecorder()
			route.ServeHTTP(rec, req)

			if gotMethod != http.MethodPut {
				t.Fatalf("sidecar method %q, want PUT (denyVerbsWithBody must not swallow it)", gotMethod)
			}
			if gotLen != keepassWebDAVPutBytes {
				t.Fatalf("sidecar body %d bytes, want %d", gotLen, keepassWebDAVPutBytes)
			}
			if rec.Code != tt.wantClientStatus {
				t.Fatalf("client status %d, want %d", rec.Code, tt.wantClientStatus)
			}
			if tt.wantNext {
				if !nextCalled {
					t.Fatal("next was not called after sidecar allow")
				}
				if nextLen != keepassWebDAVPutBytes {
					t.Fatalf("next body %d bytes, want %d", nextLen, keepassWebDAVPutBytes)
				}
			} else if nextCalled {
				t.Fatal("next ran; sidecar 4xx must be copied as a block")
			}
		})
	}
}
