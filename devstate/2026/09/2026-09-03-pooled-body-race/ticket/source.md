# Pooled body buffer returned while HTTP transport may still read aliased bytes

Chat-originated from opus_review.md finding 3. No tracker issue.

## User instruction

Fix this. First ENSURE that we have a test that REPRODUCES the issue. Leaking bytes between requests is extremely CRITICAL. Use a dedicated worktree. Slug chosen by the agent: `2026-09-03-pooled-body-race`.

## Finding 3 (opus_review.md)

Pooled body buffer is returned to the pool while the HTTP transport may still be reading the aliased bytes.

- Severity: high
- Confidence: medium
- Location: `pkg/modsecurity/body.go:42-53` (Get/alias/release) and `pkg/modsecurity/serve.go:54-71` (defer + the two `bytes.NewReader(body)` consumers)
- Kind: race / pooling

`readInboundBody` returns `buf.Bytes()`, which aliases the pooled buffer's backing array, and a `release` closure that `Put`s that buffer back. `ServeHTTP` hands the same slice to two independent `net/http` transports: `bytes.NewReader(body)` as the sidecar request body and `io.NopCloser(bytes.NewReader(body))` as `req.Body` for `next`. `http.Client.Do` returns as soon as response headers are read; the request body is written by `persistConn.writeLoop` on a separate goroutine. The same is true of `httputil.ReverseProxy` inside `next`. So `defer releasePooledBuffer()` firing when `ServeHTTP` returns does not guarantee nobody is still reading.

The race is: goroutine A is inside `bytes.Reader.Read` on the pooled array (transport writeLoop); goroutine B, serving an unrelated request, has just `Get`-ed the same `*bytes.Buffer`, called `buf.Reset()`, and is running `io.Copy(buf, req.Body)` into that same array.

Trigger: a body larger than the socket send buffer (roughly >64 KB, well within the 8 MB `maxBodySizeBytes` / 5 MB pool cap defaults) so the write cannot complete before the response arrives, plus a peer that responds before draining. Both are ordinary: ModSecurity/CRS returns 403 immediately on a rule hit without reading the rest of the upload, and backends routinely answer 401/413/302 to a large POST without consuming it.

Impact: unsynchronized concurrent access to the same memory (a genuine Go data race), and semantically one request's body bytes being written onto another request's WAF or backend connection — request-body cross-contamination between tenants.

Fix sketch from the audit: do not let the pooled array escape into anything the transport owns. Either copy out before building the readers, or keep the alias but make release wait until the sidecar request body was consumed. Copying is far simpler. To confirm the bug, run `go test -race` with a WAF stub that writes 403 and returns immediately (no body read) against a ~1 MB POST, looping concurrently so the pool recycles.
