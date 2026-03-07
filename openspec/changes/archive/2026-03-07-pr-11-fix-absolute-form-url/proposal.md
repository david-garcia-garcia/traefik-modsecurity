## Why

When an HTTP client sends a request in **absolute-form** (`POST http://example.com/path HTTP/1.0`), the plugin concatenates the full URL into the ModSecurity forwarding URL, producing an invalid double-scheme URL (`http://waf:8080http://example.com/path`). This causes DNS resolution failures and silently drops WAF inspection for affected requests.

## What Changes

- Replace `req.RequestURI` with `req.URL.RequestURI()` in the URL construction for ModSecurity forwarding in `ServeHTTP`
- `req.URL.RequestURI()` always returns origin-form (`/path?query`), regardless of how the original request was received

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `waf-proxy-request-forwarding`: The requirement for how the WAF forwarding URL is constructed changes — it must normalise absolute-form RequestURIs to origin-form before concatenation.

## Impact

- **Code**: Single line change in `ServeHTTP` (`modsecurity.go` line ~250)
- **Behaviour**: Fixes breakage for HTTP/1.0 clients and any client or upstream proxy that sends absolute-form request URIs; no behaviour change for standard HTTP/1.1 origin-form requests
- **Tests**: New unit test case(s) needed in `modsecurity_test.go` covering absolute-form input; existing tests unaffected
