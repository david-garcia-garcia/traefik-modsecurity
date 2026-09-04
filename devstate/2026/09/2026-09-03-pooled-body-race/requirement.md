# Requirement
IssueKey: 2026-09-03-pooled-body-race

## Problem

A pooled inbound-body buffer is Put back when `ServeHTTP` returns, while the sidecar (and possibly `next`) HTTP transport may still be reading the slice that aliases that buffer. Another request can then Get the same `*bytes.Buffer`, Reset it, and overwrite the backing array. That is a Go data race and can write one tenant's request body onto another request's WAF or backend connection.

The human requires a test that **reproduces** this leak on current `main` **before** the production fix. A test that only stays green is not enough.

## Current (code)

- `pkg/modsecurity/body.go:48-59` — pooled path `Get`s a `*bytes.Buffer`, `Reset`s it, copies the inbound body in, returns `buf.Bytes()` (alias of the backing array) plus a `release` that `Put`s the buffer when `Cap()` is at or under the pool cap.
- `pkg/modsecurity/body.go:27-28` — comment says the caller must defer `release` so Put happens after `ServeHTTP` (including `next`).
- `pkg/modsecurity/serve.go:54-56` — `defer releasePooledBuffer()` on the pooled path.
- `pkg/modsecurity/serve.go:67-70` — the same `body` slice is wrapped in `bytes.NewReader` for the sidecar `http.Client.Do` and in `io.NopCloser(bytes.NewReader(body))` for `req.Body` / `next`.
- `pkg/modsecurity/serve.go:109-116` — a sidecar 3xx/4xx copies the block page and returns without calling `next`. That is the early-return path the audit names.
- `pkg/modsecurity/body_pool_test.go` `TestPlugin_ConcurrentMixedBodySizesDoNotRace` — concurrent mixed sizes on one core; the WAF stub `ReadAll`s the body and payloads are 200 / 4096 bytes. It does not leave the sidecar unread, and it does not use a body larger than a typical socket send buffer.
- `openspec/specs/core_plugin_middleware_body-pool/spec.md` — concurrent mixed-size requirement asserts each request keeps its own body and `go test -race` is clean, but the scenario does not name an early sidecar response that skips reading the POST.
- `knowledge/devdocs/core_plugin_middleware.md` — gotcha says defer `release` from `ServeHTTP` so Put stays after `next`; it does not say the transport may still hold the aliased bytes after that return.

## Desired

- A regression test that fails on current `main` by showing either a `go test -race` hit on the pooled array **or** observed cross-request body bytes (one POST's payload appearing in another request's sidecar or `next` body). The reproducing setup is a WAF stub that answers 403 without reading the POST, a pooled body large enough that the write cannot finish before headers return (~1 MiB is the audit's sketch), and concurrent `ServeHTTP` so the pool recycles.
- After that test exists and has been seen failing, stop letting the pooled backing array escape into anything `net/http` owns. Copy-out before building the readers, or equivalent that keeps Put from racing a live reader.
- After the fix, that same test must pass with `-race`, and no request may observe another request's body bytes.

## Affected

- `pkg/modsecurity/body.go`
- `pkg/modsecurity/serve.go`
- `pkg/modsecurity/body_pool_test.go`
- `openspec/specs/core_plugin_middleware_body-pool/spec.md`
- `knowledge/devdocs/core_plugin_middleware.md` (Put-after-next guidance)

## Out of scope

- Other opus_review.md findings (WebSocket bypass, unanchored bypass regex, 3xx-as-block, hop-by-hop already on `main`, aggregate body-memory cap, deny-verb case, `(0, nil)` Read, Expect 100-continue, trailers, reclaim races).
- Changing `maxBodySizeBytes` / `maxBodySizeBytesForPool` defaults.
- Dropping the body buffer pool entirely.
- Making `next` / Traefik ReverseProxy drain bodies it did not already drain.

## Unknowns

- Whether this module's Go 1.21 `http.Client.Do` returns before `Request.Body` is fully written on a 403-without-read sidecar (research in flight: Client.Do request-body lifetime).
- Whether the `next` / ReverseProxy half of the alias is reachable in Traefik's proxy, or only the sidecar `Do` half reproduces.
- Exact payload size that outruns the test machine's socket send buffer; 1 MiB is the starting point, not a measured floor.

## Tensions

- The body-pool spec already claims concurrent mixed-size reads do not race; the existing test passes because the WAF consumes the body. This ticket says that coverage is the gap, not that the spec's concurrent invariant is wrong.
- The usage doc treats defer-after-`next` as the Put safety rule; the ticket says returning from `ServeHTTP` is not the same as the transport finishing the body write.
- Human: reproduce first, then fix. Do not land the production copy/wait change before a failing reproduction is recorded.
