# Explore

## Concepts

**Reporter panic (#5)**:
[acouvreur/traefik-modsecurity-plugin#5](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/5) blames Yaegi on `isWebsocket` (v1.1.0 line 56) during an HTTP/2 abort of an empty font GET. This plugin’s `isWebsocket` (`pkg/modsecurity/serve.go`) ranges `Header.Values`; a missing or nil map is a nil slice.

**Server-shaped empty GET**:
`httptest.NewRequest(..., nil)` sets `http.NoBody`. Traefik/`net/http` servers do the same. That path must not panic. A hand-built `req.Body == nil` is not a server request.

**Inbound cancel**:
Sidecar `Do` uses `req.Context()` (`core_plugin_middleware_request-context`). Cancel is an error return (502), not a plugin nil-deref.

**HTTP/2 RST_STREAM**:
A client cancel after the handler starts may panic `http.ErrAbortHandler` when the handler writes after reset. That is server abort, not a plugin nil-deref.

**Residual nil Body**:
Default `denyVerbsWithBody` includes GET. `MaxBytesReader.Read` on a nil Body panics. Caller forbids `recover` and behavior change. Document only.

```
inbound GET (empty / cancel / HTTP/2 RST)
        │
        ▼
   isWebsocket? ──yes──► next (skip WAF)
        │ no
        ▼
   denyVerbsWithBody peek (GET) ── nil Body ──► panic (residual)
        │ NoBody / empty
        ▼
   sidecar Do(req.Context()) ── Canceled ──► 502, no health trip
        │
        ▼
   allow → next   |   write-after-RST → ErrAbortHandler (server)
```

## Decisions

- Land `pkg/modsecurity/upstream_issue_05_test.go` as-is. Helpers already match `New` / `ForRoute` / `CreateConfig`. Measured: `go test ./pkg/modsecurity -run TestPlugin_UpstreamIssue05` passed (1.106s).
- No product change. No `recover` in ServeHTTP.
- OpenSpec records the no-panic invariants by folding onto existing leaves (`websocket-skip`, `request-context`). Do not invent a new ServeHTTP panic owner unless FindSpecHost says `new`.
- Usage docs already name handshake skip and inbound cancel. No new Language.

## Open questions

- Q: Who owns client address, user, tenant, Host, or trust hop for this change?
  Decision: assumed — none. Tests do not set or reconstruct identity. Incoming Host stays on `req.Host`; Traefik owns forwarded headers (`knowledge/research/ext_traefik_proxy_forwarded-headers`).
  By: explore

- Q: Keep the starter test that expects panic on `req.Body == nil`?
  Decision: assumed — yes. It documents the residual deny-verb peek. Do not add `recover` or change the peek.
  By: explore

- Q: Treat `http.ErrAbortHandler` on HTTP/2 client abort as a pass?
  Decision: assumed — yes. That is Go server abort after RST_STREAM, not a plugin nil-deref. Fail only on any other panic.
  By: explore

- Q: Clone acouvreur/traefik-modsecurity-plugin to pin v1.1.0 line 56?
  Decision: assumed — no. This run pins this plugin’s Go tests. Ticket scratch stays in `devstate/`. Existing websocket + request-context research is enough.
  By: explore

- Q: New spec leaf vs fold onto `websocket-skip` and `request-context`?
  Decision: assumed — fold. `isWebsocket` no-panic belongs on `core_plugin_middleware_websocket-skip`. Cancel / HTTP/2 abort no nil-deref belongs on `core_plugin_middleware_request-context`. FindSpecHost at propose confirms.
  By: explore

- Q: Write a Go `Header.Values` research folder?
  Decision: assumed — no. Stdlib `Header.Values` on a missing/nil map is a nil slice; the tests pin it. Existing `ext_http_*` packets already cover cancel and the handshake.
  By: explore
