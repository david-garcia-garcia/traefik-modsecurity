## Why

After the sidecar request inherited the inbound context, a client disconnect makes `httpClient.Do` return an error and today's path still records a WAF health failure. A disconnect flood can trip fail-open and let later requests skip the WAF. The parent change parked this classification on purpose.

## What Changes

- When the inbound request context is already done, do not record the `Do` error as a WAF health failure.
- Still record real sidecar and transport errors as health failures.
- Still record `timeoutMillis` (`http.Client.Timeout`) as a health failure when the inbound context stays live.
- Add unit tests for inbound cancel (no trip) and client timeout (trip).
- Do not change tracker threshold, window, backoff, or the fail-open path.

## Capabilities

### New Capabilities

- `core_plugin_middleware_health-failures`: Which sidecar `Do` errors count as WAF health failures. Inbound-context cancel or deadline SHALL NOT. Client timeout and other sidecar/transport errors SHALL.

### Modified Capabilities

None.

## Impact

- `pkg/modsecurity/serve.go` — `Do` error path only
- `pkg/modsecurity/serve_test.go` — cancel vs client-timeout health tests
- `knowledge/devdocs/core_plugin_health.md` and `core_plugin_middleware.md` — usage lines that say every `Do` error is a failure
- No public config, header, or API change
