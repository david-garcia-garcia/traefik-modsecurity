# Requirement
IssueKey: 2026-09-03-regex-bypass-clear

## Problem

Operators can write a natural-looking `bypassRules.pathRegexp` such as `/health` or `/search/v1/statement/executing/` and believe it is a prefix or exact-path allowlist. The matcher is Go RE2 `Regexp.MatchString` on `req.URL.Path`: unanchored substring search. A pattern without `^` / `$` / `\A` / `\z` can skip the WAF for unintended paths. The review asked to auto-anchor. The human said do not auto-anchor; make the contract obvious so the operator owns anchors.

## Current (code)

- `pkg/modsecurity/bypass.go:115-131` — `compiledBypass.match` runs `re.MatchString(req.URL.Path)` (decoded path, no extra normalize).
- `pkg/modsecurity/bypass.go:51` — each operator pattern is wrapped `(?:pattern)` then joined with `|`; no `\A` / `^` is inserted.
- `pkg/modsecurity/config.go:18-19` — `BypassRule` comment says optional method and path regexp; empty fields match everything. It does not say MatchString is unanchored or that the operator must write anchors.
- `pkg/modsecurity/bypass_test.go:24-65` — fixtures use `/search/v1/statement/executing/` and `/health` as if they were prefixes; no case shows `health` matching `/unhealthy` or a later path segment.
- `README.md:242-256` — already states MatchString is unanchored and shows `^/health$` as exact. The example still has unanchored `pathRegexp: /healthz` next to anchored `^/admin/`.
- `openspec/specs/core_plugin_middleware_bypass-rules/spec.md:19-59` — requirements say `req.URL.Path` **contains a match**. Scenarios use unanchored `/health` and `/search/v1/statement/executing/` without a substring-hit scenario.
- `knowledge/devdocs/core_plugin_middleware.md:71` — implementer packet already says MatchString is unanchored (`health` matches `/unhealthy`).

## Desired

Keep match semantics: unanchored RE2 `MatchString` on `req.URL.Path`. Do not wrap operator patterns with `\A` or `\z`. Document, in every operator-facing surface that describes `pathRegexp`, that:

1. The pattern is unanchored substring search.
2. Prefix or exact matching is the operator’s job (`^…`, `^…$`, or `\A` / `\z`).
3. Examples must not look like prefix/exact rules while omitting anchors.

## Affected

- Operator docs: `README.md` `bypassRules` comments.
- Type comment: `pkg/modsecurity/config.go` `BypassRule`.
- Spec: `openspec/specs/core_plugin_middleware_bypass-rules/spec.md` (via a new OpenSpec change).
- Tests: `pkg/modsecurity/bypass_test.go` only if needed to lock the documented unanchored contract (substring hit still bypasses).

## Out of scope

- Auto-anchoring compiled patterns (`\A(?:pattern)` / `\z`).
- Changing the match subject to `RawPath` / `EscapedPath()`, or refusing bypass when those disagree.
- Rejecting requests whose path contains `.` / `..` segments as a bypass guard.
- Changing method matching, compile-join, or ServeHTTP skip order.

## Unknowns

- How much of the review’s decoded-path vs backend-target mismatch should appear in operator docs vs stay a known RE2/`net/url` fact. Explore will decide.

## Tensions

- Review fix sketch: wrap every pattern as prefix/exact by construction. Human: operator writes `^`; plugin does not rewrite the pattern.
- README already warns about unanchored MatchString, then shows `/healthz` without `^` or `$`.
- Spec wording “contains a match” is accurate; scenario tables still look like prefix allowlists.
