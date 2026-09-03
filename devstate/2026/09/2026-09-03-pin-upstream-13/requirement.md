# Requirement
IssueKey: 2026-09-03-pin-upstream-13

## Problem

Upstream [acouvreur/traefik-modsecurity-plugin#13](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/13) reports Authelia login failing after WAF attach, with access-log `POST /api/firstfactor` **405**. This repo must pin in a unit test that **this plugin does not invent 405** on that POST: allow sidecar → `next` (not 405); sidecar 405 → copied block. Tests only.

## Current (code)

- `pkg/modsecurity/serve.go` never writes `http.StatusMethodNotAllowed`. Local statuses are 400 (`denyVerbsWithBody` body), 413 (oversize body), 502 (WAF failure / inbound cancel), or a copy of sidecar 3xx/4xx via `forwardResponse` (`rw.WriteHeader(resp.StatusCode)`).
- Sidecar status `>= 300 && < 500` (includes 405) is a security block: copy response, do not call `next` (`pkg/modsecurity/serve.go`; spec `openspec/specs/core_plugin_middleware_sidecar-response/spec.md`).
- Sidecar status below 300: drain sidecar body, restore inbound body, call `next`.
- `CreateConfig` default `DenyVerbsWithBody` is HEAD/GET/DELETE/OPTIONS/TRACE/CONNECT (`pkg/modsecurity/config.go`). **POST is not on that list**; a POST body is not rejected with 400 or 405.
- Sidecar request: `proxyReq.Host = req.Host`; headers copied as-is; `RemoteAddr` is not appended to `X-Forwarded-For`; plugin does not set `X-Real-IP` (`pkg/modsecurity/serve.go`; spec `openspec/specs/core_plugin_middleware_sidecar-request/spec.md`).
- Host/XFF copy is already covered on GET `/protected` by `pkg/modsecurity/serve_test.go` `TestPlugin_SidecarRequestCopiesHostAndForwardingHeaders`.
- No Authelia-shaped POST `/api/firstfactor` test in this tree except the untracked starter `pkg/modsecurity/upstream_issue_13_test.go`.
- No Authelia service or ForwardAuth labels in compose (`docker-compose.yml` / test compose). Official Authelia documents POST `/api/firstfactor` as 200/401, not 405 (`knowledge/research/ext_authelia_api_firstfactor/notes.md`).

## Desired

Land `pkg/modsecurity/upstream_issue_13_test.go` (adapt if `origin/main` APIs differ): `POST /api/firstfactor` with portal Host, leftover XFF, `X-Real-Ip`, and a login POST body.

- Allow sidecar (2xx): client is `next` (not 405); body restored; sidecar sees POST, that path, that body, inbound Host, copied XFF/`X-Real-Ip` without `RemoteAddr` appended.
- Sidecar 405: client 405 and sidecar page; `next` skipped.

## Affected

- `pkg/modsecurity/upstream_issue_13_test.go` (add/adapt)
- Existing `New` / `ForRoute` / `CreateConfig` / `NewLogger` seams in `pkg/modsecurity` (tests only; no runtime change)

## Out of scope

- Authelia or ForwardAuth compose, Traefik chain examples, or README Authelia docs
- A plugin knob for 405
- Changing Host/XFF/`denyVerbsWithBody` runtime behavior
- Closing or commenting on the upstream GitHub issue
- Integration tests against a live Authelia portal

## Unknowns

- Whether the starter file compiles against this worktree's `New` / `ForRoute` / `NewLogger` (it matches `pkg/modsecurity/plugin.go` and `route.go` on this HEAD; confirm at implement).
- Authelia official body is JSON; the starter uses form-urlencoded. Acceptable: the test is a plugin fixture, not an Authelia client (`knowledge/research/ext_authelia_api_firstfactor/notes.md`).

## Tensions

- Upstream thread treats 405 as ModSecurity "method not allowed." CRS method-not-allowed is typically 403, not 405. This ticket does not require proving CRS status; it requires proving this plugin does not invent 405.
- Parent-checkout analysis (`modsecissues/issue-13-authelia.md`) said "no product work." This caller overrides: **tests only**, land the starter coverage.
