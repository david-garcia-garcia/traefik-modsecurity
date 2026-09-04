## Context

See proposal.md Why. `readInboundBody` (`pkg/modsecurity/body.go`) returns `buf.Bytes()` plus a `release` that Puts the `*bytes.Buffer`. `ServeHTTP` defers that Put and wraps the same slice in two `bytes.NewReader`s. Official `bytes.Buffer.Bytes` aliases the backing array until the next Reset/Write. Official `RoundTrip` / `Client.Do` may read `Request.Body` after return (`knowledge/research/ext_http_client_request-body-lifetime/`, `ext_golang_bytes_buffer-bytes/`).

Explore measured a throwaway RoundTripper: after Put, the first sidecar read was 1048576 bytes of `0xBB` (the second POST) and zero `0xAA`. A real `http.Transport` 403-without-read does not keep the TCP conn past Put (`wroteRequest` 50 ms then `pc.close`), so the product assertion is the RoundTripper contract, not a hijacked socket.

## Goals / Non-Goals

**Goals:**

- Owned copy of pooled body bytes before sidecar/`next` readers exist
- Regression test that fails on current `main` by reproducing the `0xAA`→`0xBB` leak, then passes after copy-out
- Usage gotcha: Put only after the copy, not merely after `next`

**Non-Goals:**

- Removing the body buffer pool
- Changing `maxBodySizeBytes` / `maxBodySizeBytesForPool` defaults
- Waiting on `resp.Body.Close` or writeLoop instead of copying
- Asserting a leak on a live `persistConn` TCP capture
- Other opus_review.md findings

## Decisions

1. **Copy-out, not wait-until-consumed.** `append([]byte(nil), buf.Bytes()...)` (or equivalent) then Put. `resp.Body.Close` does not wait for writeLoop; `Do` returning is not idle. Alternative (delay Put until Body Close) is easy to get wrong and still races if Close is async.

2. **Put after the copy, not after `next`.** Once transports own the copy, the buffer can return immediately. `release` may Put inside `readInboundBody` after the copy, or still be deferred; either is safe. Prefer Put right after the copy so the buffer is not held for the WAF round-trip.

3. **Regression seam is a test `http.RoundTripper`.** Replace `plugin.httpClient.Transport`. First request: return 403, read Body only after first `ServeHTTP` returns. Second request: same core, different fill byte. Sticky single-buffer pool makes Get/Put deterministic. Existing `TestPlugin_ConcurrentMixedBodySizesDoNotRace` stays (it drains the WAF body).

4. **Fold into `core_plugin_middleware_body-pool`.** FindSpecHost: fold, high, candidates `core_plugin_middleware_body-pool`, `core_plugin_middleware_sidecar-request`, `core_plugin_middleware_maxbodysize`. The delta is pool-alias lifetime, not sidecar Host or max size.

5. **Identity.** None. Do not set or reconstruct client address, user, tenant, Host, or trust hop.

## Risks / Trade-offs

- [Extra alloc equal to body size on the pooled path] → Same order as today's alias; pool still avoids repeated growth during `io.Copy` into the buffer. Ad-hoc path (`io.ReadAll`) already owns its slice.
- [Windows agent cannot `go test -race`] → Semantic leak test is the local gate; CI `-race` if the workflow enables CGO.
- [Sticky pool is test-only] → Production `sync.Pool` is still racy without copy-out; the sticky pool makes the FAIL deterministic.

## Migration Plan

No Config or deploy change. Operators keep the same image wiring. Rollback: revert the copy-out; leak returns.

## Open Questions

None that change specs. See `devstate/explore.md` assumed rows (copy-out, RoundTripper test, fold, no local `-race`).
