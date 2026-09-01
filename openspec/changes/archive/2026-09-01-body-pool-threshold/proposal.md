## Why

`maxBodySizeBytesForPool` is meant to keep `bodyBufferPool` from retaining large backing arrays. The pool decision reads the `Content-Length` header, which net/http removes for chunked requests, so those bodies always use the pool and grow up to `maxBodySizeBytes`. Nothing checks `buf.Cap()` before `Put`, so concurrent chunked uploads can leave the pool holding max-size buffers.

## What Changes

- Decide pool vs ad-hoc allocation from `req.ContentLength` (treat `-1` as unknown).
- After a pooled read, return the buffer to `bodyBufferPool` only when `buf.Cap() <= maxBodySizeBytesForPool`.
- Document that decision and the Put gate in README (correct the stated default to 5 MiB to match `CreateConfig`).
- Add unit coverage for unknown length and for not retaining an oversized pooled buffer.

## Capabilities

### New Capabilities

- `core_plugin_middleware_body-pool`: When the plugin buffers a request body, choose the pool from `req.ContentLength` and do not Put a buffer whose capacity exceeds `maxBodySizeBytesForPool`.

### Modified Capabilities

None.

## Impact

- `pkg/modsecurity/serve.go` — pool decision and Put.
- `modsecurity_test.go` — unknown-length and pool-cap cases.
- `README.md` — `maxBodySizeBytesForPool` mechanism text.
- No new config keys. No change to `maxBodySizeBytes` / 413 behavior.
- Downstream handlers that retain `req.Body` after `ServeHTTP` returns are unchanged (still alias the pooled slice).
