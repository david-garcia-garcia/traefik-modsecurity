## Why

A ModSecurity sidecar 3xx (`redirect` or `deny,status:302`) is treated as allow. The plugin only blocks on status `>= 400`, and the WAF HTTP client follows `Location`, so the request the WAF intercepted still reaches the backend with no log and no status header.

## What Changes

- Treat sidecar status `>= 300` as a block: copy that response to the client and do not call `next`.
- Stop the shared WAF `http.Client` from following redirects so `Do` returns the sidecar's own 3xx and `Location`.
- Keep allow as HTTP success (`< 300`). No new config key.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_sidecar-response`: allow is status below 300 (not 400); block is 300 or higher; the WAF client must not follow redirects.

## Impact

- `pkg/modsecurity/serve.go` block condition
- `pkg/modsecurity/plugin.go` WAF client `CheckRedirect`
- `modsecurity_test.go` ServeHTTP table (302 / Location cases)
- `knowledge/devdocs/core_plugin_middleware.md` usage line for the block threshold
- No public config, API, or header change
