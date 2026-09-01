## Why

The sidecar request takes `Host` from `ModSecurityUrl` and never appends the peer IP to `X-Forwarded-For`. CRS host rules and ModSecurity's audit log therefore see the sidecar hostname and lose the client address.

## What Changes

- After the existing header copy, set the sidecar request `Host` from the incoming `req.Host`.
- Append the peer IP from `req.RemoteAddr` to `X-Forwarded-For` the way `httputil.ReverseProxy` Director does (`SplitHostPort`, join any prior values, `Set`). Parse failure leaves the header unchanged.
- Tests assert the mock WAF sees the original Host and the appended chain (no prior, prior values, IPv6, unparseable `RemoteAddr`).
- No public config key. No `X-Real-IP`, `X-Forwarded-Host`, or `X-Forwarded-Proto`.

## Capabilities

### New Capabilities

- `core_plugin_middleware_sidecar-request`: What identity the sidecar HTTP request carries (`Host` and `X-Forwarded-For`).

### Modified Capabilities

None.

## Impact

- `pkg/modsecurity/serve.go` (sidecar request construction)
- Unit tests that inspect the mock WAF request
- Middleware usage packet after implement (`knowledge/devdocs/core_plugin_middleware.md`)
- No Traefik catalog / YAML config change
