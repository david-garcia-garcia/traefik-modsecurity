## Context

See proposal.md Why. `isWebsocket` already tokenizes `Connection` / `Upgrade` via `Header.Values`. ServeHTTP already binds the sidecar call to `req.Context()`. The gap is tests that the reporter shape from [acouvreur/traefik-modsecurity-plugin#5](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/5) does not panic.

Helpers on origin/main match the starter file: `New(name, cfg, logger)`, `ForRoute`, `CreateConfig`, `Close`.

## Goals / Non-Goals

**Goals:**

- Land `pkg/modsecurity/upstream_issue_05_test.go` (adapt only if compile fails).
- Keep product ServeHTTP unchanged.

**Non-Goals:**

- `recover` in ServeHTTP.
- Fixing the residual panic when a hand-built `req.Body` is nil on a deny-verb GET.
- Changing handshake rules or cancel/health classification.

## Decisions

- **Tests only, no product edit.** Alternative: add `recover` around ServeHTTP. Rejected: hides real bugs and is forbidden by the ticket.
- **Keep the nil-Body panic test.** Alternative: delete it. Rejected: explore assumed we document the residual.
- **Pass on `http.ErrAbortHandler` after HTTP/2 RST.** Alternative: fail any panic. Rejected: that is Go server abort, not a plugin nil-deref.
- **Fold specs, do not invent a serve-no-panic leaf.** FindSpecHost: small additions to `core_plugin_middleware_websocket-skip` and `core_plugin_middleware_request-context`.

## Risks / Trade-offs

- [HTTP/2 test needs TLS + h2] → `httptest` `EnableHTTP2` + `StartTLS` as in the starter file. Fail if proto is not `HTTP/2.0`.
- [Flaky cancel races] → wait on sidecar `started` before cancel; bound waits with `t.Fatal`.
- [Residual nil Body] → documented test only; operators never see it on a real server.

## Migration Plan

None. Tests land with the PR. No deploy or config change.

## Open Questions

None. Assumed decisions live on `devstate/explore.md`.
