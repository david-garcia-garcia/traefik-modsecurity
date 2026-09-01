## 1. Write failing test

- [x] 1.1 Add a Go unit test that drives `New` + `ServeHTTP` with a sidecar 403 that sets `Connection: close`, `Server`, `Content-Type`, a `Proxy-*` header, and a `Connection`-listed custom hop, then asserts status and body stay and those hop/`Server` headers are absent. Confirm the test fails on current `forwardResponse`.

## 2. Filter block-path headers

- [x] 2.1 In `forwardResponse` (or a helper it calls in `pkg/modsecurity`), skip hop-by-hop names (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `Upgrade`, `Proxy-*` prefix, `Te`, `Trailer`), names listed in sidecar `Connection`, and `Server`. Keep overwrite copy for remaining headers and stream the body.
- [x] 2.2 Re-run the unit test from 1.1 and existing `pkg/modsecurity` tests until they pass.

## 3. Document client-visible error page

- [x] 3.1 Update README How it works so it states that on block the sidecar error-page body is returned to the client, and that hop-by-hop/`Server` headers are not copied.
- [x] 3.2 Update the block-path bullet and a gotcha on `knowledge/devdocs/core_plugin_middleware.md` to match the filter. Append the path on `devstate/knowledge.md`.
