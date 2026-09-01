## Context

See proposal.md for motivation. Body read lives in `pkg/modsecurity/serve.go`. `bodyBufferPool` is a package-level `sync.Pool` of `*bytes.Buffer`. `CreateConfig` sets `MaxBodySizeBytes` to 8 MiB and `MaxBodySizeBytesForPool` to 5 MiB. net/http sets `req.ContentLength` to the parsed length or `-1` when unknown; it deletes the `Content-Length` header on chunked requests.

## Goals / Non-Goals

**Goals:**

- Use `req.ContentLength` as the only size input for the pool vs ad-hoc choice.
- Drop a pooled buffer when `buf.Cap()` exceeds `maxBodySizeBytesForPool`.
- Cover unknown length and the Put gate in package tests that can see `bodyBufferPool`.

**Non-Goals:**

- Copying `buf.Bytes()` so a handler that retains `req.Body` after return is safe.
- Changing default numeric limits.
- Changing 413 / `MaxBytesReader` behavior.

## Decisions

### Decision: Unknown length still uses the pool

When `req.ContentLength < 0`, set `usePool` true. Known length uses `usePool = req.ContentLength <= p.maxBodySizeBytesForPool`.

Rationale: the attack is retention of grown buffers, not peak bytes of one request (already capped by `maxBodySizeBytes`). Skipping the pool on every chunked body would allocate ad-hoc for small uploads and would leave the Put gate unused on the path the ticket names.

Alternative: `usePool = false` when unknown. Safer against a single large chunked read touching a pooled buffer, but worse for typical small chunked bodies.

### Decision: Put is gated on capacity, not on Len

`if buf.Cap() <= p.maxBodySizeBytesForPool { bodyBufferPool.Put(buf) }`. Compare `Cap`, not `Len`, because `bytes.Buffer` may have grown past the last write.

Alternative: never Put. That would disable reuse for small bodies.

### Decision: Tests that inspect the pool live in `pkg/modsecurity`

Root `modsecurity_test.go` cannot see `bodyBufferPool`. Add cases in `pkg/modsecurity` next to `serve_test.go`. Existing size-limit tests in the root package stay; they already assert 413 vs pass.

### Decision: README mechanism text only

Rewrite the `maxBodySizeBytesForPool` bullets to describe `req.ContentLength` and the Cap() Put gate. Set the documented default to 5 MiB (`5242880`) to match `CreateConfig`. Leave the YAML example value as an operator override if it already shows a non-default number.

## Risks / Trade-offs

- [Risk] A large chunked body still grows a pooled buffer for the duration of that request → Mitigation: `MaxBytesReader` still caps at `maxBodySizeBytes`; Put will not retain it.
- [Risk] Tests that inspect `sync.Pool` can flake if another test leaves a large buffer → Mitigation: `Get` after the request under test, assert Cap, and do not Put an oversized buffer back from the test.
- [Risk] Downstream `next` that retains `req.Body` after return can still see recycled bytes → Mitigation: out of scope; documented as Handler-contract behavior.

## Migration Plan

No config migration. Deploy is a plugin rebuild. Rollback is revert the ServeHTTP decision/Put change.

## Open Questions

None. The `-1` choice is recorded on `devstate/explore.md`.
