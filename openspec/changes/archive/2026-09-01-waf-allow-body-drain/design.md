## Context

`Plugin.ServeHTTP` proxies each inspected request to `ModSecurityUrl` on a shared `http.Client`. A status below 400 is allow: restore `req.Body` and call `next`. A status of 400 or higher is block: `forwardResponse` copies the sidecar body to the client (that path already drains).

The allow path only `Close`s `resp.Body`. Against this repo's sidecar (`BACKEND=http://dummy` / whoami) the allow body is a few hundred bytes with `Content-Length`, so `Close` happens before EOF. Go 1.26 `http.Transport` then skips `tryPutIdleConn`. Go 1.27 auto-drains on `Close`; this plugin runs inside Traefik v3.7.12 (Go 1.26).

## Goals / Non-Goals

**Goals:**

- Reuse the sidecar TCP connection on sequential allow-path requests when the unread body is within 256 KiB.
- Guard that with a `httptest` `ConnState` test.

**Non-Goals:**

- Public drain-cap or timeout config
- Changing block/allow status rules
- Retuning Pester performance tests or adding `Benchmark*`
- HTTP/2 stream reuse (sidecar URL is `http://`)

## Decisions

- Drain inline on the allow path with `io.Copy(io.Discard, io.LimitReader(resp.Body, 256<<10))` immediately before `next`. The existing deferred `Close` still runs.
- Cap is 256 KiB, hardcoded, same byte cap as Go 1.27. A body larger than the cap still leaves unread bytes; that connection is not reused (same as today).
- Ignore copy errors: headers are not sent from this body, and `Close` still runs. Do not fail the client request because drain failed.
- Test lives in `pkg/modsecurity` and drives `New` + `ForRoute` with a whoami-sized 200 body. Assert one `StateNew` across many sequential allows. Empty-body control may stay as a second case if it documents the EOF-already-reuses rule.

## Risks / Trade-offs

- [A pathological sidecar that trickles a large body] → `LimitReader` bounds bytes; a slow trickle can still hold the request until `http.Client.Timeout`. Acceptable; do not add a second deadline.
- [Drain adds a read on the hot path] → whoami-sized bodies are hundreds of bytes. Measured cheaper than a new dial.
- [Go 1.27 Traefik later auto-drains] → explicit drain stays correct and documents the contract for older runtimes.

## Migration Plan

No migration. Deploy the plugin; idle-pool settings apply without config changes.

## Open Questions

None. Cap and test placement are decided in `devstate/explore.md`.
