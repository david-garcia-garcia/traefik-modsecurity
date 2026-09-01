## 1. Write failing test

- [x] 1.1 In `pkg/modsecurity`, add a test that POSTs with `req.ContentLength == -1` and a body larger than `maxBodySizeBytesForPool` (still under `maxBodySizeBytes`), then `Get`s from `bodyBufferPool` and fails if that buffer's `Cap()` exceeds the pool cap.
- [x] 1.2 Add a test that sets `req.ContentLength` above the pool cap while omitting or shrinking the `Content-Length` header, then asserts the request still passes to `next` and the pool does not retain a buffer of that size.
- [x] 1.3 Run those new tests and confirm they fail on current `serve.go` (header-only decision + unconditional Put).

## 2. Core implementation

- [x] 2.1 In `pkg/modsecurity/serve.go`, decide `usePool` from `req.ContentLength`: known length uses `contentLength <= maxBodySizeBytesForPool`; `-1` uses the pool.
- [x] 2.2 Replace the unconditional `defer bodyBufferPool.Put(buf)` with a Put only when `buf.Cap() <= p.maxBodySizeBytesForPool`.
- [x] 2.3 Remove the unused `strconv` / header-string parse if nothing else in the file needs it.

## 3. Docs and existing tests

- [x] 3.1 Update the `maxBodySizeBytesForPool` mechanism bullets in `README.md` to describe `req.ContentLength` and the Cap() Put gate, and correct the documented default to 5 MiB.
- [x] 3.2 Re-run the new package tests plus existing body-size tests in `modsecurity_test.go` (`TestModsecurity_BodySizeLimit_WhenNotUsingPool`, `TestModsecurity_BodySizeLimit_WithoutContentLength`) and confirm they pass.
