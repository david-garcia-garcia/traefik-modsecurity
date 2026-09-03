# Requirement
IssueKey: 2026-09-03-add-bypass-routes

## Problem

Operators need a config knob so selected request method+path patterns skip the ModSecurity sidecar (admin/high-frequency routes). A prior fork (DNAstack `04c04549`) added `bypassRules` with `method` and `pathRegexp`, but `matchesBypassRule` walks every compiled rule per request. That linear scan does not scale. This tree has no such knob. The status-header token for a regex skip must be `bypassrule`.

## Current (code)

- `pkg/modsecurity/config.go` `Config` has no `BypassRules` / `BypassRule` field (`not found`).
- `pkg/modsecurity/plugin.go` `Plugin` has no compiled bypass map (`not found`).
- `pkg/modsecurity/serve.go` `ServeHTTP` early-exits only for a WebSocket handshake (`isWebsocket`) and for an already-unhealthy health tracker (`unhealthy` on `modSecurityStatusRequestHeader`). Neither is an operator regex allowlist.
- `pkg/modsecurity/serve.go` writes status-header tokens `unhealthy`, `error`, `blocked`, `ok`. Token `bypassrule` is `not found`.
- `openspec/specs/core_plugin_middleware_status-header/spec.md` lists `blocked`, `error`, `unhealthy`, `ok`. It does not name `bypassrule`.
- `openspec/specs/core_plugin_middleware_websocket-skip/spec.md` is the only operator-independent WAF skip. It does not set a status header.
- README Configuration (`README.md`) documents `modSecurityStatusRequestHeader` values `ok` / `blocked` / `error` / `unhealthy`. No `bypassRules`.
- Named fork surface (ticket): `BypassRule{Method, PathRegexp}` and `Config.BypassRules []BypassRule`. Internals compile one regexp per rule and scan the slice in `matchesBypassRule`.

## Desired

- Public config matches the named fork: `bypassRules` list of `{ method, pathRegexp }`. Both specified: both must match. Method-only or path-only still bypass (fork tests).
- Internals: one map lookup `VERB -> compiled *regexp.Regexp`. Per method, concatenate that method's path regexes (each grouped/escaped so `|` join is safe) into a single compiled expression. One `MatchString` per request after the map lookup. Do not keep a per-rule slice scan.
- Invalid `pathRegexp` fails plugin construction (`Prepare` / `New`).
- Empty / omitted `bypassRules` keeps today's inspect-all behavior.
- When a request matches a bypass rule and `modSecurityStatusRequestHeader` is set, write `bypassrule`, then call `next` without reading the body or calling the sidecar. Empty header name: still skip, add no header.
- Performance: the bypass check runs before inbound body buffering.

## Affected

- `pkg/modsecurity/config.go` (`BypassRule`, `Config.BypassRules`, Prepare validation)
- `pkg/modsecurity/plugin.go` (compiled `map[string]*regexp.Regexp`)
- `pkg/modsecurity/serve.go` (early exit + `bypassrule` header)
- `openspec/specs/core_plugin_middleware_status-header/spec.md` (new token)
- New spec leaf for bypass rules (propose picks host)
- `README.md` configuration example
- Tests under `pkg/modsecurity/` (compile, match, header, miss, invalid regexp)

## Out of scope

- Changing WebSocket skip semantics or giving it a status-header token
- Changing health-tracker fail-open (`unhealthy`)
- Adopting the fork's module-path / `.traefik.yml` import rename
- Per-rule tracing of *which* regexp matched (one combined expression cannot name a source rule)
- Admin UI (this plugin has none)

## Unknowns

- Whether `escaped` means `regexp.QuoteMeta` (literalize `pathRegexp`, changing fork regex semantics) or non-capturing-group wrap of each already-valid regex before `|` join
- Where path-only rules (empty method) live in a VERB map so lookup stays one map get
- Whether bypass runs before or after `denyVerbsWithBody` / WebSocket checks
- Spec host: fold onto `status-header` vs new `core_plugin_middleware_bypass-rules` leaf

## Tensions

- Ticket wants the fork's user-facing surface (regex `pathRegexp`) and also `escaped` concatenation. `QuoteMeta` would make `pathRegexp` a literal, which is not the fork's compile-as-regex behavior.
- Ticket wants exactly one lookup. Path-only rules apply to every method; a missing map key needs a fallback without a second scan of a rule list.
- WebSocket skip currently writes no status header. Regex bypass must write `bypassrule` when the name is set. A handshake that also matches a bypass rule can only have one token.
