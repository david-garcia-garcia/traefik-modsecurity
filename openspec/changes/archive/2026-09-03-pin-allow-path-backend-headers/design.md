## Context

See `proposal.md` Why. Allow path already calls `next.ServeHTTP(rw, req)` after `discardSidecarBody` (`pkg/modsecurity/serve.go`). Block path copies sidecar headers via `forwardResponse`. The starter test at `pkg/modsecurity/upstream_issue_29_test.go` already matches current `New` / `ForRoute` / `Close` APIs and measured PASS.

## Goals / Non-Goals

**Goals:**

- Commit the starter test as the lock for allow-path `next` headers on a real `ResponseWriter` and `httptest.Recorder`.
- Record the header invariant on `core_plugin_middleware_sidecar-response`.

**Non-Goals:**

- Any `ServeHTTP` edit.
- Yaegi / Traefik wrapper repro.
- Changing block-path `forwardResponse`.

## Decisions

- **Land the starter file unchanged.** It already uses package helpers (`CreateConfig`, `New`, `NewLogger`, `ForRoute`) the same way as `serve_test.go`. Alternative: rewrite as a case in `TestPlugin_SidecarResponseReusesConnection` — rejected; that test owns connection reuse, not CORS.
- **Two writers.** `httptest.NewServer` is a real `net/http` `ResponseWriter` (`requestTooLarge` implementer). `httptest.Recorder` is not. Both are required so a MaxBytesReader interaction cannot hide on one surface. Alternative: recorder only — rejected; that is the reporter’s weaker hypothesis surface.
- **Fold, do not add a leaf.** FindSpecHost: small adjustment to `core_plugin_middleware_sidecar-response` (high). Alternative: new `core_plugin_middleware_allow-headers` — rejected; “client gets `next`’s response” already lives on this leaf.

## Risks / Trade-offs

- [Yaegi wrapping can still drop headers in production] → Out of scope. A later Traefik+Yaegi report is a new ticket.
- [OPTIONS is in `denyVerbsWithBody` with an empty body] → The starter’s OPTIONS has no body; the one-byte probe continues. Do not empty the deny list in this test.

## Migration Plan

None. Tests and spec only. Rollback is revert the commit.

## Open Questions

None. Remaining unknowns are recorded on `devstate/explore.md` as assumed Decisions.
