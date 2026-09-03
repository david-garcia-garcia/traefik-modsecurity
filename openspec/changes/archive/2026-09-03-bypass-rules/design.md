## Context

See proposal.md Why. `ServeHTTP` today early-exits only for a WebSocket handshake and an already-unhealthy tracker. `Config` has no allowlist. Research: `ext_dnastack_modsecurity_bypass-rules` (linear scan), `ext_golang_regexp_alternation` (`(?:p)|(?:q)` join; do not QuoteMeta operator regexes), `ext_traefik_plugins_nested-config` (Yaegi mapstructure matches Go field names).

## Goals / Non-Goals

**Goals:**
- One map get of the request method, then at most one `MatchString` on `req.URL.Path`.
- Same operator YAML as the named fork (`bypassRules` / `method` / `pathRegexp`).
- Fail construction on an invalid regexp.

**Non-Goals:**
- Naming which source rule matched (a combined expression cannot).
- QuoteMeta of operator `pathRegexp` (that would change the fork surface).
- Changing WebSocket skip when no bypass rule matches.
- Admin UI.

## Decisions

- **Compile a `map[string]*regexp.Regexp` keyed by uppercase method, plus `bypassAnyMethod` for methods not in the map.** Path-only patterns are concatenated into every method entry and into that fallback. Alternative: keep `[]compiledBypassRule` and scan (fork). Rejected: ticket forbids the linear scan.
- **Join with `(?:pattern)|(?:pattern)`.** Alternative: `QuoteMeta` each string then join. Rejected: QuoteMeta literalizes PathRegexp (`ext_golang_regexp_alternation`).
- **Validate each non-empty `pathRegexp` in `Prepare`; build the combined map in `New` into Plugin fields.** Alternative: store compiled regexps on Config. Rejected: Config must stay JSON-hashable for `pluginKey`.
- **Match `req.URL.Path`, not RequestURI.** Same as the fork; query string is not path.
- **Uppercase method at compile and lookup.** Alternative: exact string like the fork. Rejected: YAML `get` should match Traefik `GET`.
- **Bypass check first in ServeHTTP.** Alternative: after websocket / denyVerbsWithBody. Rejected: ticket wants skip before body read; matching GET-with-body should not 400.
- **New file `pkg/modsecurity/bypass.go`.** Compile and match are one domain, distinct from Config DTO and from ServeHTTP.
- **New spec leaf `core_plugin_middleware_bypass-rules`; fold token into `status-header`.** Alternative: one spec for both. Rejected: status tokens already have a host; the allowlist is a new capability.

## Risks / Trade-offs

- [Unanchored MatchString: `health` matches `/unhealthy`] → Mitigation: same as the fork and Go regexp; operators who need exact match write `^/health$`. Document in README.
- [Empty `pathRegexp` matches every path] → Mitigation: same as fork `Compile("")`; spec method-only explicitly.
- [Combined regexp cannot say which rule fired] → Mitigation: out of scope; one token `bypassrule`.
- [Bypass first skips denyVerbsWithBody] → Mitigation: specified; this is skip-the-WAF, not extra local policy on those routes.

## Migration Plan

Omitted `bypassRules` is a no-op. Operators add the list when they want skips. Rollback: remove the key; inspect-all returns.

## Open Questions

None. Ticket questions live on `devstate/explore.md`.
