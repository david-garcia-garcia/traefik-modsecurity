# Explore
IssueKey: 2026-09-03-pooled-body-race

## Concepts

```
  inbound POST          pooled *bytes.Buffer
       │                        │
       ▼                        ▼
  readInboundBody ──► buf.Bytes()  ── alias, not a copy
       │                        │
       ├─ bytes.NewReader(body) ─┴─► sidecar RoundTrip / writeLoop
       └─ NopCloser(NewReader) ────► next
                              ServeHTTP returns
                              defer Put ──► next Get + Reset
                              (backing array still readable)
```

**Body buffer pool** (existing Language): reuse pool of `bytes.Buffer` on one Plugin core.

**Pooled body alias**: the `[]byte` from `buf.Bytes()`. Official `bytes.Buffer.Bytes` says that slice is valid only until the next `Reset`/`Write`. `readInboundBody` returns it anyway.

**Sidecar body lifetime**: `Client.Do` / `RoundTrip` may return after response headers while another goroutine still `Read`s `Request.Body`. Owner: `knowledge/research/ext_http_client_request-body-lifetime/`.

## Decisions

- Reproduce first, then copy-out. Do not Put a buffer whose `Bytes()` slice is still reachable from a transport.
- The product regression test uses a `http.RoundTripper` that returns 403 immediately and reads `Request.Body` only after `ServeHTTP` has returned (Put). That is the documented RoundTripper contract, not a fake of a different bug.
- Fold the new invariant into `core_plugin_middleware_body-pool`. Do not invent a second body-pool spec.

## Reproduction (measured)

Throwaway `TestThrowaway_PooledBodyCrossRequestLeak` against this worktree (HEAD at explore start: `c587c7e`, same `body.go`/`serve.go` as `origin/main` `6dae0ab`):

- Sticky pool: one `*bytes.Buffer` for every Get.
- Custom `RoundTripper`: first POST returns 403 with a 5-byte page and does **not** read `req.Body` until a channel fires; second POST discards its body immediately.
- 1 MiB `0xAA` then 1 MiB `0xBB`, both under the 5 MiB pool cap.
- After first `ServeHTTP` returns (Put), run the second POST (Get + `Reset` + copy `0xBB`), then let the first sidecar body read run.

Command: `go test -count=1 -timeout 30s -v ./pkg/modsecurity -run TestThrowaway_PooledBodyCrossRequestLeak`

Result: **FAIL** in 0.00s.

```
first sidecar body read after Put: 1048576 bytes 0xAA=0 0xBB=1048576
cross-request leak: first sidecar body contains 1048576 bytes from the second request (0xBB)
```

The first WAF-side read saw **only** the second tenant's bytes. That is request-body cross-contamination, not just a race-detector finding.

### What did not reproduce (and why)

Real `httptest` + `http.Transport` 403-without-read: `Client.Do` does return before the POST write finishes (`wroteRequest` waits 50 ms then gives up). Then `readLoop` exits and `pc.close()` tears down the TCP conn. A hijacked server then observed ~21–135 KiB of `0xAA` and **no** `0xBB` — the remaining write was aborted, not crossed with the next Get. Slowing Dial writes did not keep the conn alive past Put.

`TestPlugin_ConcurrentMixedBodySizesDoNotRace` still passes: the WAF stub `ReadAll`s the body, so writeLoop finishes before Put.

Local `go test -race`: **not run**. This Windows toolchain is `CGO_ENABLED=0` / no gcc (`go: -race requires cgo`). CI Linux is the `-race` surface.

## Approaches

| Approach | What it does | Cost |
| --- | --- | --- |
| Copy-out | `append([]byte(nil), buf.Bytes()...)` then Put the buffer; transports own the copy | Extra alloc equal to body size; pool still avoids the *read* growth | 
| Wait-until-consumed | Keep the alias; delay Put until sidecar Body Close and `next` finish | Easy to get wrong: `resp.Body.Close` does not wait for writeLoop; `Do` returning is not idle |
| Drop the pool | Always `io.ReadAll` | Bound the ask: pool stays |

Copy-out is the fix. After copy, Put can run as soon as the read finishes (release may become a no-op or fire immediately). Do not keep the alias on `req.Body` for `next` either — same slice, same rule.

## Usage gap

`knowledge/devdocs/core_plugin_middleware.md` says defer `release` so Put happens after `next` because `buf.Bytes()` aliases the pooled array. That is necessary but not sufficient: Put after `ServeHTTP` is still too early for a RoundTripper that reads Body later. Implement / devdocsimpact updates that gotcha. No new Language term.

## Open questions

- Q: Copy-out or wait until the sidecar body is consumed?
  Decision: assumed — copy-out before any transport owns the slice. Waiting on Close/`next` does not match writeLoop / RoundTripper lifetime.
  By: explore

- Q: Should the regression test use a real `http.Transport` 403-without-read?
  Decision: assumed — no, not as the pass/fail assertion. Measured: persistConn closes the conn, so the wire never shows the second request's bytes. Use a RoundTripper that holds Body until after Put; that is the official contract.
  By: explore

- Q: Who already owns client address, user, tenant, Host, or trust hop for this change?
  Decision: assumed — none. This change does not set or reconstruct those fields.
  By: explore

- Q: Spec host for the new invariant?
  Decision: resolved — fold onto `core_plugin_middleware_body-pool` (FindSpecHost: high; candidates body-pool, sidecar-request, maxbodysize).
  By: propose

- Q: Local `go test -race` on this Windows agent?
  Decision: assumed — not available (`CGO_ENABLED=0`). Semantic leak test is the local proof; CI `-race` if the workflow already runs it.
  By: explore
