# Requirement
IssueKey: 2026-09-03-pin-upstream-14

## Problem

The plugin half of [acouvreur/traefik-modsecurity-plugin#14](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/14) must be pinned in tests: a 228565-byte WebDAV `PUT` is not a denied-verb body, fits the 8 MiB plugin cap, is forwarded to the sidecar, and a sidecar 400/413 is copied as a security block. There is no in-tree `PUT` + this size case on `origin/main`.

## Current (code)

- `CreateConfig` default `DenyVerbsWithBody` is `HEAD`, `GET`, `DELETE`, `OPTIONS`, `TRACE`, `CONNECT`. `PUT` is not listed (`pkg/modsecurity/config.go`).
- `CreateConfig` default `MaxBodySizeBytes` is `8 * 1024 * 1024`. `Prepare` fills omitted `0` to that default (`pkg/modsecurity/config.go`).
- A listed method with a body returns HTTP 400 before the sidecar and before `next` (`pkg/modsecurity/serve.go` deny-verb check).
- Inbound bodies at or under the cap are read by `readInboundBody` and sent on the sidecar request; `req.Body` is restored for `next` (`pkg/modsecurity/body.go`, `pkg/modsecurity/serve.go`).
- A sidecar `3xx`/`4xx` is copied with `forwardResponse` and `next` is not called (`pkg/modsecurity/serve.go`).
- Existing tests cover POST inspect-and-forward, GET/DELETE+body 400, local oversize 413, and sidecar 413 copy (`pkg/modsecurity/modsecurity_test.go`, `deny_verbs_with_body_test.go`, `body_pool_test.go`). No `PUT` / 228565-byte KeePass case on `origin/main`.
- Starter file `pkg/modsecurity/upstream_issue_14_test.go` is untracked. It calls `New`, `NewLogger`, `ForRoute`, `Close` — those APIs exist on `origin/main` (`pkg/modsecurity/plugin.go`, `pkg/modsecurity/route.go`).
- CRS-docker default `MODSEC_REQ_BODY_NOFILES_LIMIT=131072` (128 KiB) is sidecar policy, not a plugin field. Existing research: `knowledge/research/ext_modsecurity_http-status_deny-vs-error/notes.md`. Modern engine reject is 413; old rule 200002 was 400.

## Desired

- Land the starter tests (adapt only if APIs differ): `TestCreateConfig_PutIsNotDeniedAndKeepassSizeFitsDefaultCap` and `TestPlugin_KeepassWebDAVPutIsForwardedAndSidecar4xxCopied` (allow / sidecar 400 / sidecar 413).
- Tests only. No `Config` field, no `ServeHTTP` change, no plugin knob that shadows `SecRequestBodyNoFilesLimit`.

## Affected

- `pkg/modsecurity/upstream_issue_14_test.go` (new)

## Out of scope

- README / demo `docker-compose.yml` `MODSEC_REQ_BODY_NOFILES_LIMIT` notes (docs P2).
- A plugin product knob that shadows sidecar `SecRequestBodyNoFilesLimit`.
- README 5 MB / “0 = unlimited” drift (issue 20).
- Live CRS-docker nofiles integration test.
- Dummy-hop 416/AH01084, inspect-only sidecar.

## Unknowns

- Whether the untracked starter compiles without edits against this `origin/main` (APIs appear to match; confirm at implement).
- Remote CI workflow names and duration (measure after the stub PR exists).

## Tensions

- Upstream #14’s save failure is sidecar `SecRequestBodyNoFilesLimit` (128 KiB), not this plugin. This ticket pins the plugin half only and leaves the operator/docs gap out of scope.
- A plugin knob that raised nofiles locally would lie about who rejects the body; caller forbids that.
