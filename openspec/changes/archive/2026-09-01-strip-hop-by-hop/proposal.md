## Why

On a WAF block, `forwardResponse` copies every sidecar response header to the client. That forwards hop-by-hop fields (`Connection: close` closes the client keep-alive) and the sidecar `Server` banner (Apache/ModSecurity version). Operators also may not realize the sidecar error-page body is what the client sees.

## What Changes

- On the block path, strip hop-by-hop headers (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `Upgrade`, any `Proxy-*` name, `Te`, `Trailer`, and names listed in the sidecar `Connection` field) and `Server` before copying the sidecar response to the client.
- Keep copying the sidecar status and error-page body (existing documented behavior).
- Document that the sidecar error page is client-visible.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_sidecar-response`: block path still returns sidecar status and body, but MUST NOT forward hop-by-hop headers or `Server`.

## Impact

- `pkg/modsecurity/serve.go` (`forwardResponse`)
- Block-path unit tests
- `README.md` How it works
- Usage gotcha on `knowledge/devdocs/core_plugin_middleware.md`
- No new config key. Not **BREAKING** for allow traffic. Blocked clients stop seeing sidecar `Server` and hop-by-hop headers.
