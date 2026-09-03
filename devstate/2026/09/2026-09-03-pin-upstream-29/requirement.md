# Requirement
IssueKey: 2026-09-03-pin-upstream-29

## Problem
[acouvreur/traefik-modsecurity-plugin#29](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/29) reports that when the sidecar allows a request, the client keeps backend body and status but loses backend response headers (CORS `Access-Control-Allow-*` and others). This ticket asks for durable native-Go tests that prove that loss does **not** happen on this rewrite: WAF 200, `next` sets CORS + `X-Backend`, those headers survive on `httptest.Server` and `httptest.Recorder`, and sidecar headers do not leak. Tests only.

## Current (code)
- Allow path (`pkg/modsecurity/serve.go`): sidecar status below 300 → `discardSidecarBody` → optional request-header `ok` → `next.ServeHTTP(rw, req)`. The allow path does not copy sidecar response headers onto `rw`.
- Block path (`pkg/modsecurity/serve.go` `forwardResponse`): sidecar 3xx/4xx copies sidecar headers onto `rw`. Opposite of allow.
- Inbound body (`pkg/modsecurity/body.go`): when `maxBodySizeBytes > 0` (CreateConfig default 8 MiB), `req.Body = http.MaxBytesReader(rw, req.Body, p.maxBodySizeBytes)`. Oversize is 413 via `replyInboundBodyReadFailure`, not allow.
- Denied-verb probe (`pkg/modsecurity/serve.go`): `http.MaxBytesReader(rw, req.Body, 1)` on listed methods; empty GET/OPTIONS continue.
- Existing allow test (`pkg/modsecurity/serve_test.go` `TestPlugin_SidecarResponseReusesConnection` / `allow 200`): asserts client 200 and body `"next"`. The stub `next` writes no CORS / custom backend headers.
- Root status-header allow case (`modsecurity_test.go`): asserts request header `ok` plus body/status. Stand-in service writes empty `http.Header{}`.
- Starter coverage is untracked at `pkg/modsecurity/upstream_issue_29_test.go` (`TestPlugin_UpstreamIssue29_AllowPathKeepsBackendHeaders`). It uses current APIs: `CreateConfig`, `New`, `NewLogger`, `ForRoute`, `Close` (`pkg/modsecurity/plugin.go`, `pkg/modsecurity/route.go`, `pkg/modsecurity/config.go`).

## Desired
- Land `pkg/modsecurity/upstream_issue_29_test.go` so a WAF 200 plus `next` CORS/`X-Backend` stay on the client for GET, OPTIONS, and POST on both `httptest.NewServer` (real `ResponseWriter`) and `httptest.Recorder`.
- Sidecar headers (e.g. `X-Waf`) must not appear on the client.
- Adapt the starter only if origin/main APIs differ. Do not change `ServeHTTP`.

## Affected
- `pkg/modsecurity/upstream_issue_29_test.go` (new durable test)
- OpenSpec / usage docs only if propose finds a host for the allow-path header invariant

## Out of scope
- Any `ServeHTTP` or `forwardResponse` change
- Yaegi / Traefik `ResponseWriter` wrapping (unit tests cannot prove production Yaegi)
- Unwrapping `MaxBytesReader` after the body read
- Moving sidecar `resp.Body.Close` for this issue
- Copying sidecar headers onto the client on allow

## Unknowns
- Whether an existing spec already states allow-path backend response-header preservation
- Whether Yaegi wrapping can still lose headers in Traefik (explicitly out of scope)

## Tensions
- Upstream issue remains OPEN on the Yaegi plugin. This ticket pins native Go only; it does not close or fix the reporter’s Traefik+Yaegi observation.
