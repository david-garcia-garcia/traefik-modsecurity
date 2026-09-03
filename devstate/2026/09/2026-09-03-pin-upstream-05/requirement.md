# Requirement
IssueKey: 2026-09-03-pin-upstream-05

## Problem
[acouvreur/traefik-modsecurity-plugin#5](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/5) reports an HTTP/2 abort / Yaegi panic blamed on `isWebsocket`. This fork has no regression tests that prove our `isWebsocket` and ServeHTTP path do not panic on that reporter shape (empty GET, inbound cancel, HTTP/2 RST_STREAM).

## Current (code)
- `isWebsocket` (`pkg/modsecurity/serve.go`) returns true only for GET + `Connection` token `upgrade` + `Upgrade` equal-fold `websocket`. It uses `Header.Values`; a missing or nil header map yields a nil slice and `range` is safe.
- `Plugin.ServeHTTP` (`pkg/modsecurity/serve.go`) calls `isWebsocket` first; a handshake skips the sidecar and calls `next`. There is no `recover` in product ServeHTTP.
- Default `denyVerbsWithBody` includes GET (`pkg/modsecurity/config.go`). A hand-built `req.Body == nil` on GET reaches `MaxBytesReader.Read` and panics. Traefik/`net/http` servers set `http.NoBody`.
- Sidecar call uses `http.NewRequestWithContext(req.Context(), …)` (`pkg/modsecurity/serve.go`; usage `knowledge/devdocs/core_plugin_middleware.md`). Inbound cancel is a client error, not a plugin nil-deref (`knowledge/research/ext_http_client_request-context/notes.md`).
- Handshake skip contract: `openspec/specs/core_plugin_middleware_websocket-skip/spec.md`.
- Starter tests exist untracked: `pkg/modsecurity/upstream_issue_05_test.go`. Helpers match current APIs (`New`, `NewLogger`, `ForRoute`, `CreateConfig`, `Close`).

## Desired
Land that test file (adapt only if APIs differ): `isWebsocket` does not panic; a reporter-shaped empty GET does not panic; inbound cancel / HTTP/2 client abort does not nil-deref. Tests only. Do not add `recover` in ServeHTTP. Do not change product behavior.

## Affected
- `pkg/modsecurity/upstream_issue_05_test.go` (new)

## Out of scope
- Adding `recover` in ServeHTTP
- Changing `isWebsocket`, deny-verb peek, or any product path
- Fixing the documented residual nil-`Body` panic
- Changing the upstream acouvreur plugin

## Unknowns
- Whether the starter file compiles and passes on this tree (APIs match by inspection; not run yet)
- Whether Yaegi still attributes a later panic to `isWebsocket` (this run pins Go-test behavior, not a Yaegi interpreter)

## Tensions
- The starter file includes a test that **expects** panic on `req.Body == nil`. That documents a residual; it is not a product fix. Caller forbids `recover` and behavior change.
