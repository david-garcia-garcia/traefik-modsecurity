## Why

On the allow path the plugin closes the ModSecurity sidecar response without reading the body. Go 1.26's HTTP client (Traefik v3.7.12) then drops that TCP connection instead of returning it to the idle pool, so `MaxIdleConns` and `MaxIdleConnsPerHost` do not apply to almost all traffic.

## What Changes

- On a sidecar status below 400, read the leftover response body up to 256 KiB and discard it before `Close`.
- Add a unit test that counts new connections to a mock WAF across sequential allowed requests.
- No public config knob. No change to the Pester WAF-vs-bypass comparison.

## Capabilities

### New Capabilities

- `core_plugin_middleware_sidecar-response`: How the plugin finishes the sidecar HTTP response on allow vs block so the shared client can reuse the connection.

### Modified Capabilities

None.

## Impact

- `pkg/modsecurity/serve.go` allow path
- A Go test next to `ServeHTTP`
- Operators see no new keys. Existing idle-pool settings start working for allow-path traffic.
