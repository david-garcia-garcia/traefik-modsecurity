# Requirement
IssueKey: 2026-09-03-pin-upstream-11

## Problem

[acouvreur/traefik-modsecurity-plugin#11](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/11) reports a large non-file POST becoming a client HTTP 500. This repo must pin that that outcome does not happen here: plugin oversize is 413 `blocked`; sidecar 413 is copied as a block; sidecar 5xx is 502 `error`. Never a forwarded client 500. Tests only.

## Current (code)

- Local oversize: `pkg/modsecurity/body.go` `readInboundBody` wraps `req.Body` in `http.MaxBytesReader` when `maxBodySizeBytes > 0`. Content-Type is not inspected; file vs non-file is not a plugin distinction.
- Local 413: `pkg/modsecurity/serve.go` `replyInboundBodyReadFailure` type-asserts `*http.MaxBytesError` and writes HTTP 413 plus status-header `blocked`. Other inbound read errors are 502.
- Sidecar 413: `pkg/modsecurity/serve.go` `ServeHTTP` treats `300 <= status < 500` as a security block (`forwardResponse`, header `blocked`). Health is not recorded.
- Sidecar 5xx: same function treats `status >= 500` as a WAF failure (`recordWafFailureAndReplyToClient`). With `unhealthyWafBackOffPeriodSecs == 0` the client gets HTTP 502 and header `error`. The sidecar 5xx body is not copied.
- Existing tests cover the three mappings separately (`TestPlugin_Sidecar413DoesNotTripHealth`, `TestModsecurity_Sidecar5xxIsWafFailure`, `TestModsecurity_StatusHeader_BodyTooLarge` and body-limit cases in `modsecurity_test.go` / `pkg/modsecurity/serve_test.go`). No committed test names the upstream issue or uses a large non-file form POST as the fixture.
- Starter file (untracked): `pkg/modsecurity/upstream_issue_11_test.go` — table of those three cases on a 6 MiB `application/x-www-form-urlencoded` POST. APIs (`New`, `NewLogger`, `ForRoute`, `CreateConfig`) match `pkg/modsecurity/plugin.go` and `pkg/modsecurity/route.go` on this tree.

## Desired

Land the starter coverage (adapt only if APIs differ). Assert: never client 500; plugin cap → 413 `blocked` and no sidecar hit; sidecar 413 → 413 `blocked`; sidecar 500 → 502 `error`. Do not change status mapping.

## Affected

- `pkg/modsecurity/upstream_issue_11_test.go` (new)

## Out of scope

- Changing status mapping or fail-open thresholds
- Adding a file vs non-file plugin distinction
- Sidecar `MODSEC_REQ_BODY_NOFILES_LIMIT` / engine config
- Runtime / plugin production code
- Raising default `timeoutMillis` for large POSTs

## Unknowns

- Whether propose should add a new spec leaf or only a scenario on the existing `core_plugin_middleware_waf-status` / sidecar-response specs (tests-only ticket; mapping already specified).
- Whether the 6 MiB fixture needs a higher `timeoutMillis` in unit tests (in-process httptest; default 2s may or may not matter).

## Tensions

- Ticket asks for dedicated #11 coverage even though the three mappings already have other unit tests. The new file is the pin; do not treat existing tests as a reason to skip it.
- Reporter’s file-vs-text split is an engine `SecRequestBodyNoFilesLimit` fact (`knowledge/research/ext_modsecurity_http-status_deny-vs-error/notes.md`, `knowledge/devdocs/core_plugin_middleware.md` gotcha). Not a plugin API gap.
