# Requirement
IssueKey: 2026-09-03-pin-upstream-09

## Problem

Upstream [acouvreur/traefik-modsecurity-plugin#9](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/9) reported that 1.2.0 returned `body max limit reached: http: request body too large` on a login-form POST. The mechanism is `http.MaxBytesReader` with limit `0` (Yaegi-omitted or leftover handler field), which rejects any non-empty body as `*http.MaxBytesError`. This tree must keep tests that prove that path does not 413 a login-sized POST. Tests only.

## Current (code)

- `pkg/modsecurity/config.go` `CreateConfig` sets `MaxBodySizeBytes` to `8 * 1024 * 1024`.
- `pkg/modsecurity/config.go` `Prepare` remaps `MaxBodySizeBytes == 0` to that CreateConfig default (omitted and explicit `0` both become 8 MiB).
- `pkg/modsecurity/plugin.go` `New` copies the prepared value onto `Plugin.maxBodySizeBytes`.
- `pkg/modsecurity/body.go` `readInboundBody` wraps `req.Body` with `http.MaxBytesReader` only when `p.maxBodySizeBytes > 0`. A leftover handler field `0` skips the wrapper.
- `pkg/modsecurity/serve.go` `replyInboundBodyReadFailure` maps `*http.MaxBytesError` to HTTP 413.
- `pkg/modsecurity/route.go` `ForRoute` + `Route.ServeHTTP` is the test seam (`New` + stub WAF + stub next).
- Starter (untracked): `pkg/modsecurity/upstream_issue_09_test.go` — four cases: omitted config, explicit `0`, forced handler `0`, and stdlib `MaxBytesReader(0)` as the 1.2.0 mechanism.
- `openspec/specs/core_plugin_middleware_prepare-validation/spec.md` says a zero numeric field keeps today’s meaning (CreateConfig default). It does not name the #9 POST-413 pin or the `> 0` MaxBytesReader skip.
- No `knowledge/research/` folder for `MaxBytesReader` zero-limit (gap; written this prepare).

## Desired

- Land (or adapt) `pkg/modsecurity/upstream_issue_09_test.go` so it compiles and passes on this tree’s `New` / `ForRoute` / `Prepare` APIs.
- Omitted `maxBodySizeBytes` and operator `0` prepare to 8 MiB; a login-sized POST is 200 and calls next.
- A leftover handler `maxBodySizeBytes == 0` does not 413 that POST (skip `MaxBytesReader`).
- Keep the stdlib pin that `MaxBytesReader(0)` still returns `*http.MaxBytesError` on a small body.
- Do not change product cap behavior.

## Affected

- `pkg/modsecurity/upstream_issue_09_test.go` (new test file)
- Possibly a spec leaf for the #9 pin (propose decides host)
- Research: `knowledge/research/ext_http_maxbytesreader/` (Go `MaxBytesReader` limit 0)

## Out of scope

- README / docs drift for the default (`#20`)
- Changing CreateConfig default, Prepare remap, or the `> 0` MaxBytesReader guard
- Changing 413 behavior for a body that actually exceeds a positive `maxBodySizeBytes`
- Product code changes unless the starter cannot compile against origin/main APIs (adapt tests only)

## Unknowns

- Whether propose folds the #9 pin into `core_plugin_middleware_prepare-validation` or adds a new spec leaf
- Whether `NewLogger` before `Prepare` (starter calls `NewLogger` with unprepared cfg) is accepted; `New` calls `Prepare` after

## Tensions

- `prepare-validation` already says zero remaps to CreateConfig default, but does not require a login POST to stay 200 or the leftover-handler skip. Ticket asks tests that pin those outcomes, not a product change.
- Ticket says do not change product cap behavior; starter asserts 8 MiB after Prepare. That matches `CreateConfig` today.
