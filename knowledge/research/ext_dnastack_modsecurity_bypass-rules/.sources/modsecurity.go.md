---
url: https://github.com/DNAstack/traefik-modsecurity-plugin/blob/04c04549f54f0bb0f34330393669b63f5fd1be05/modsecurity.go
title: modsecurity.go BypassRule
fetched: 2026-09-03
authority: source
ref: github.com/DNAstack/traefik-modsecurity-plugin@04c04549f54f0bb0f34330393669b63f5fd1be05:modsecurity.go
---

Commit message: `[CU-86b94z4aw] Add bypassRules to skip modsecurity sidecar for high-frequency paths`.

```go
type BypassRule struct {
    Method     string `json:"method,omitempty"`
    PathRegexp string `json:"pathRegexp,omitempty"`
}

type Config struct {
    TimeoutMillis   int64        `json:"timeoutMillis"`
    ModSecurityUrl  string       `json:"modSecurityUrl,omitempty"`
    MaxBodySize     int64        `json:"maxBodySize"`
    BypassRules     []BypassRule `json:"bypassRules,omitempty"`
}
```

`CreateConfig` sets timeout and MaxBodySize only.

`New` loops `config.BypassRules`, `regexp.Compile(r.PathRegexp)`, wraps errors as `invalid bypass rule pathRegexp %q: %w`, stores `compiledBypassRule{method, pathRegexp}`.

`ServeHTTP`: websocket skip, then `if a.matchesBypassRule(req) { a.next.ServeHTTP(rw, req); return }`, then body read / sidecar.

`matchesBypassRule`: linear scan; skip rule if method non-empty and ≠ `req.Method`; skip if `pathRegexp != nil` and `req.URL != nil` and `!pathRegexp.MatchString(req.URL.Path)`; else return true. Empty method = any method.
