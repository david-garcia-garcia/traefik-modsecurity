## Why

The outbound WAF request is built with `http.NewRequest`, so it is bound to `context.Background()` rather than the inbound Traefik request context. A client disconnect or Traefik deadline leaves the sidecar call running until `timeoutMillis`, holding a `MaxConnsPerHost` slot the whole time.

## What Changes

- Build the sidecar request with `http.NewRequestWithContext(req.Context(), req.Method, url, bodyReader)` in `pkg/modsecurity/serve.go`.
- Add a unit test that cancels the inbound context while a mock WAF is blocked and asserts the sidecar call stops instead of running to `timeoutMillis`.
- Keep `http.Client.Timeout` (`timeoutMillis`). Do not change pool limits or health-tracker error classification.

## Capabilities

### New Capabilities

- `core_plugin_middleware_request-context`: The sidecar HTTP request inherits the inbound request context so a canceled inbound context cancels the WAF call.

### Modified Capabilities

None.

## Impact

- `pkg/modsecurity/serve.go` — WAF request construction
- `pkg/modsecurity/serve_test.go` — cancel-while-blocked unit test
- No public config, header, or API change
