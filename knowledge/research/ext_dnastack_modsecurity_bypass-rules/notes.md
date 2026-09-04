# BypassRule Method PathRegexp

Named fork commit `04c04549f54f0bb0f34330393669b63f5fd1be05` on `DNAstack/traefik-modsecurity-plugin`. Adds `Config.BypassRules []BypassRule` with `Method` + `PathRegexp` (`json` tags). `New` compiles each `PathRegexp` once. `ServeHTTP` calls `matchesBypassRule` **before** reading the body and **before** the sidecar hop. Match is a linear scan: method (if non-empty) then `MatchString` on `req.URL.Path`.

This folder is the fork’s behavior at that commit, not this product’s tree.

## Config shape

```go
type BypassRule struct {
    Method     string `json:"method,omitempty"`
    PathRegexp string `json:"pathRegexp,omitempty"`
}

type Config struct {
    // …
    BypassRules []BypassRule `json:"bypassRules,omitempty"`
}
```

`CreateConfig` does not default `BypassRules` (nil slice).

Owner: `DNAstack/traefik-modsecurity-plugin@04c0454:modsecurity.go`.

Extract: `.sources/modsecurity.go.md`

Yaegi decode of that slice: `ext_traefik_plugins_nested-config`.

## Compile at New

For each rule, `regexp.Compile(r.PathRegexp)`. On error: `invalid bypass rule pathRegexp %q: %w` — `New` fails, plugin does not start.

Empty `PathRegexp` compiles (`Compile("")` succeeds; see `ext_golang_regexp_alternation`). The compiled `*Regexp` is stored even then. `pathRegexp` is never left nil after a successful `New`.

Owner: same file, `New`.

## Linear matchesBypassRule

Called at the top of `ServeHTTP` after the websocket skip, before `MaxBytesReader` / sidecar.

```go
for _, rule := range a.bypassRules {
    if rule.method != "" && rule.method != req.Method {
        continue
    }
    if rule.pathRegexp != nil && req.URL != nil && !rule.pathRegexp.MatchString(req.URL.Path) {
        continue
    }
    return true
}
```

- Method empty → any method.
- Method compared as exact string (`GET` ≠ `get`).
- Path uses `Regexp.MatchString` on `req.URL.Path` (unanchored; `health` matches `/unhealthy`).
- First matching rule wins. No combined alternation — one compiled regexp per rule.

Comment on the type and on `matchesBypassRule`: “Both Method and PathRegexp must match (when specified).” Specified for method is `!= ""`. Path is always a compiled regexp after `New`, so an omitted `pathRegexp` still matches every path.

Owner: same file, `matchesBypassRule` + `ServeHTTP`.

Extract: `.sources/modsecurity.go.md`

## Tests at that commit

`TestModsecurity_BypassRules` builds `[]compiledBypassRule` in the test (does not decode YAML). Cases: method+path match; method miss; path miss; method-only; path-only (`/health`); no rules.

Owner: `…@04c0454:modsecurity_test.go`.

Extract: `.sources/modsecurity_test.go.md`
