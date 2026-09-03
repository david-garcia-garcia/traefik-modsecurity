## Why

[acouvreur/traefik-modsecurity-plugin#5](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/5) reports an HTTP/2 abort / Yaegi panic blamed on `isWebsocket`. This plugin already skips only a real handshake and binds the sidecar call to the inbound context, but those invariants are not pinned by a test that the reporter shape (empty GET, inbound cancel, HTTP/2 RST_STREAM) does not panic.

## What Changes

- Add Go tests in `pkg/modsecurity/upstream_issue_05_test.go` that prove `isWebsocket` does not panic, a reporter-shaped empty GET does not panic, and inbound cancel / HTTP/2 client abort does not nil-deref.
- Record those no-panic invariants on the existing websocket-skip and request-context specs.
- Do not change product ServeHTTP behavior. Do not add `recover` in ServeHTTP.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_websocket-skip`: `isWebsocket` SHALL NOT panic when the header map is missing or nil; a server-shaped empty GET SHALL NOT panic.
- `core_plugin_middleware_request-context`: inbound cancel and HTTP/2 client abort SHALL NOT nil-deref in the plugin. `http.ErrAbortHandler` after RST_STREAM is server abort, not a plugin panic.

## Impact

- Tests only: `pkg/modsecurity/upstream_issue_05_test.go`.
- No config, deploy, or ServeHTTP product change.
- Residual: a hand-built `req.Body == nil` on a deny-verb GET still panics; documented by a test, not fixed.
