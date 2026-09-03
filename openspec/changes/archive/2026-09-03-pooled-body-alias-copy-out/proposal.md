## Why

`readInboundBody` returns `buf.Bytes()`, which aliases the pooled `bytes.Buffer`. `ServeHTTP` Puts that buffer when the handler returns, while a sidecar RoundTripper may still read `Request.Body`. A later request can Get the same buffer, Reset it, and overwrite another tenant's POST. Measured on this tree: after Put, the first sidecar body read was 1 MiB of the second request's `0xBB` and zero `0xAA`.

## What Changes

- Copy the pooled unread bytes into an owned slice before any sidecar or `next` reader is built. Put the buffer only after that copy (the pool still avoids the inbound read allocation).
- Add a regression test that fails on current `main`: 403 RoundTripper that reads `Request.Body` only after first `ServeHTTP` returns, then a second pooled POST overwrites the buffer; the first sidecar read MUST still be the first POST. Implement lands this test and records FAIL before the copy-out.
- Fold one requirement into `core_plugin_middleware_body-pool`. Update the middleware usage gotcha that says defer-after-`next` is enough.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_body-pool`: pooled inbound-body bytes SHALL NOT remain aliased to a buffer that can be Put and Reset while a sidecar or `next` reader still holds them. A RoundTripper that reads `Request.Body` after `ServeHTTP` returns SHALL still see that request's own body, not a later request's.

## Impact

- `pkg/modsecurity/body.go` (`readInboundBody` copy-out / Put timing)
- `pkg/modsecurity/serve.go` only if restore/`bytes.NewReader` needs to use the owned slice (same return)
- `pkg/modsecurity/body_pool_test.go` (leak regression; existing cap/Put tests stay)
- `openspec/specs/core_plugin_middleware_body-pool/spec.md` (archive)
- `knowledge/devdocs/core_plugin_middleware.md` (Put-after-copy gotcha)
- No Config key. No default changes. No pool removal.
