# Close forged WebSocket WAF skip (or drop auto-detection)

Local spec. Caller extras (chat, 2026-09-03):

- Issue slug: websocketbypass. IssueKey: 2026-09-03-websocketbypass.
- Use a dedicated git worktree.
- Do not implement until explore answers: (1) what other WAF products do when they cannot reliably tell a WebSocket handshake from a forged `Upgrade`; (2) whether this plugin should drop automatic WebSocket detection and rely on `bypassRules` for operator-chosen WebSocket paths.

Source finding: `opus_review.md` §1 (forged WebSocket handshake skips the WAF and leaves a client-supplied status header intact).

---

### 1. Forged WebSocket handshake skips the WAF *and* leaves a client-supplied status header intact

- **Severity:** high
- **Confidence:** high
- **Location:** `pkg/modsecurity/serve.go:28-31`, `pkg/modsecurity/serve.go:171-185`
- **Kind:** bypass

**What's wrong:** `isWebsocket` returns true for any `GET` carrying `Connection: Upgrade` and `Upgrade: websocket`, and `ServeHTTP` then calls `next.ServeHTTP` with no sidecar call at all. There is no verification that this is a real handshake (`Sec-WebSocket-Key`, `Sec-WebSocket-Version`) and no check that the route is actually a WebSocket route. Critically, this is also the *only* terminal path in `ServeHTTP` that does not `Set` `modSecurityStatusRequestHeader`: every other outcome (bypass rule, unhealthy, blocked, error, ok) overwrites it, so a backend or downstream middleware that trusts that header is right to do so — except here, where whatever the client sent survives untouched.

**Trigger:** Any client sends `GET /index.php?id=1'+OR+1=1-- HTTP/1.1` with those two headers plus, say, `X-Waf-Status: ok`. The backend is not a WebSocket endpoint, so it responds 200 normally; Go's `ReverseProxy` only diverts to raw tunneling on a 101, so the request and response are proxied as ordinary HTTP.

**Impact:** Every GET-based rule class (SQLi in query strings, path traversal, XSS reflected via GET, scanner probes) is trivially skipped by adding two request headers, and the backend sees a forged "this was inspected and allowed" marker.

**Fix sketch:** Require a genuine handshake before bypassing — at minimum `Sec-WebSocket-Key` and `Sec-WebSocket-Version: 13` present, and ideally still send the handshake (headers only, no body) to the sidecar since CRS rules apply to the URI and headers. Independently and separately from that decision, delete `modSecurityStatusRequestHeader` from `req.Header` at the very top of `ServeHTTP` so no code path can ever forward a client-supplied value.

The bypass itself is asserted as intended behavior by `modsecurity_test.go:82` ("Does not forward Websockets"), so treat the WAF-coverage half as a design question. The header-spoofing half is not covered: every WebSocket test case sets `modSecurityStatusRequestHeader: ""`.
