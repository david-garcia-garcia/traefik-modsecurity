## 1. Write failing test

- [ ] 1.1 In `pkg/modsecurity/body_pool_test.go`, add `TestPlugin_PooledBodyNotAliasedAfterPut`: sticky one-buffer pool; `http.RoundTripper` that returns 403 for the first POST and reads `Request.Body` only after that `ServeHTTP` returns; second pooled POST of a different fill byte; assert the delayed first body is the first POST and the client status is 403.
- [ ] 1.2 Run `go test -count=1 -timeout 30s -v ./pkg/modsecurity -run TestPlugin_PooledBodyNotAliasedAfterPut` on current code (no copy-out). Record FAIL with `0xBB` (or the second fill) in the first sidecar body. Do not start task 2 until that FAIL is recorded.

## 2. Copy-out

- [ ] 2.1 In `readInboundBody`, after a successful pooled `io.Copy`, copy `buf.Bytes()` into an owned slice and Put the buffer (when `Cap()` is at or under the pool cap) before returning. Do not return the aliased `buf.Bytes()` to `ServeHTTP`.
- [ ] 2.2 Keep the ad-hoc `io.ReadAll` path unchanged. Keep `ServeHTTP` building sidecar/`next` readers from the returned slice.
- [ ] 2.3 Re-run task 1.2. It SHALL pass. Run existing `./pkg/modsecurity` body-pool tests (`TestPlugin_UnknownLengthDoesNotRetainOversizedPoolBuffer`, `TestPlugin_SmallPooledReadReturnsBuffer`, `TestPlugin_ConcurrentMixedBodySizesDoNotRace`, and neighbors).

## 3. Usage and spec trail

- [ ] 3.1 Update `knowledge/devdocs/core_plugin_middleware.md` so Put happens after the copy, not merely after `next`. Alias + RoundTripper lifetime is the gotcha.
- [ ] 3.2 Leave `openspec/changes/pooled-body-alias-copy-out/specs/core_plugin_middleware_body-pool/spec.md` as the delta; archive syncs the main spec later.
