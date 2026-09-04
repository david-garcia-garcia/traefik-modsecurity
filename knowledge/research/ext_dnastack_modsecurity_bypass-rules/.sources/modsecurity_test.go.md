---
url: https://github.com/DNAstack/traefik-modsecurity-plugin/blob/04c04549f54f0bb0f34330393669b63f5fd1be05/modsecurity_test.go
title: TestModsecurity_BypassRules
fetched: 2026-09-03
authority: source
ref: github.com/DNAstack/traefik-modsecurity-plugin@04c04549f54f0bb0f34330393669b63f5fd1be05:modsecurity_test.go
---

`TestModsecurity_BypassRules` constructs `[]compiledBypassRule` in-process (no YAML / `New` decode). Asserts whether the WAF mock is called.

Cases:

- method+path match (`GET` + `/search/v1/statement/executing/` on a longer path) → no WAF
- method miss (`POST`) → WAF
- path miss (`/queued/`) → WAF
- method-only (`GET`) → no WAF on `/any/path`
- path-only (`/health`, `POST`) → no WAF
- no rules → WAF
