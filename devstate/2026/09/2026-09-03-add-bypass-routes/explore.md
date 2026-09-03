# Explore
## Concepts

**Bypass rule**:
An operator-configured pair of optional HTTP method and optional path regexp. When it matches, ServeHTTP calls next without buffering the body or calling the sidecar.
_Avoid_: router skip (Traefik router without this middleware)

**Bypass-by-method map**:
The Plugin-owned `map[string]*regexp.Regexp` keyed by uppercase method. One map get returns the only regexp that request will run. Path-only rules are merged into every method entry and into a fallback regexp used when the method key is missing.
_Avoid_: rule slice, matchesBypassRule

**Combined path regexp**:
Per method, every `pathRegexp` for that method plus every path-only pattern, each wrapped as `(?:pattern)`, joined with `|`, compiled once. Empty `pathRegexp` is an always-match for that method (fork: `Compile("")`).
_Avoid_: QuoteMeta of operator regexes (that literalizes PathRegexp)

**bypassrule**:
The `modSecurityStatusRequestHeader` token when a bypass rule matched. Distinct from `ok` (sidecar allow), `unhealthy` (health backoff), and unset WebSocket skip.

```
ServeHTTP
  |-- bypass-by-method lookup + one MatchString on URL.Path
  |     match -> set bypassrule (if header name set) -> next
  |-- isWebsocket -> next (no status token)
  |-- denyVerbsWithBody
  |-- unhealthy -> next
  |-- read body -> sidecar
```

## Decisions

- Keep the DNAstack public surface: `bypassRules: [{ method, pathRegexp }]`. Both optional; method-only and path-only still bypass (`ext_dnastack_modsecurity_bypass-rules`).
- Internals: compile in `pkg/modsecurity/bypass.go`. Store `bypassByMethod map[string]*regexp.Regexp` plus `bypassAnyMethod *regexp.Regexp` for methods not in the map. ServeHTTP does one map get of `strings.ToUpper(req.Method)`; if nil, use `bypassAnyMethod`. Then at most one `MatchString` on `req.URL.Path`.
- Join with `(?:p1)|(?:p2)` (`ext_golang_regexp_alternation`). Do not `QuoteMeta` operator regexes. Ticket "escaped" means non-capturing wrap so `|` join does not steal precedence.
- Invalid `pathRegexp` fails Prepare (same error shape as the fork). Empty omitted list: both fields nil, no bypass.
- Early return before websocket, denyVerbsWithBody, body read, and sidecar (performance; fork skipped the rest of ServeHTTP after its match).
- Traefik Yaegi mapstructure matches Go field names case-insensitively; `json` tags are docs (`ext_traefik_plugins_nested-config`). Keep `json:"bypassRules"` / `method` / `pathRegexp` like the rest of Config.
- Spec: new leaf `core_plugin_middleware_bypass-rules`; fold token `bypassrule` into `core_plugin_middleware_status-header`.
- Change name: `bypass-rules`.

## Open questions

- Q: Does "escaped" mean regexp.QuoteMeta of each pathRegexp, or `(?:pattern)` wrap before `|` join?
  Decision: assumed — wrap with `(?:...)` only. QuoteMeta would literalize PathRegexp and break the fork surface.
  By: explore

- Q: Where do path-only rules (empty method) live so lookup stays one map get?
  Decision: assumed — merge those patterns into every method's combined regexp, and keep the same combined regexp on `bypassAnyMethod` for methods not in the map. One get of req.Method; nil falls through to that fallback pointer (not a second rule scan).
  By: explore

- Q: Bypass vs WebSocket vs denyVerbsWithBody order?
  Decision: assumed — bypass first. Matching requests skip local GET-with-body reject and skip websocket detection. Token is `bypassrule` even on a handshake that also matches.
  By: explore

- Q: Spec host for the allowlist vs the status token?
  Decision: assumed — new `core_plugin_middleware_bypass-rules`; fold `bypassrule` into existing `core_plugin_middleware_status-header`.
  By: explore

- Q: Method matching case (`GET` vs `get`)?
  Decision: assumed — uppercase at compile and lookup. Fork was exact string; operators writing `get` in YAML should still match Traefik `GET`.
  By: explore

- Q: Who already owns client address / user / tenant / Host / trust hop for this skip?
  Decision: assumed — none of those facts. Match uses `req.Method` and `req.URL.Path` as net/http already parsed them. Do not reconstruct identity.
  By: explore

- Q: Should path match use URL.Path or RequestURI (query included)?
  Decision: assumed — `req.URL.Path` only, same as the fork. Query string is not part of the path regexp.
  By: explore
