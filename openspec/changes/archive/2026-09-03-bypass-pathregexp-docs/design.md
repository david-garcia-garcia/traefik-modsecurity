## Context

See proposal.md Why. Compile already wraps each `pathRegexp` as `(?:pattern)` and joins with `|`. `match` calls `Regexp.MatchString` on `req.URL.Path`. Go RE2 MatchString is substring search (`knowledge/research/ext_golang_regexp_alternation`). `req.URL.Path` is percent-decoded and is not slash-normalized.

Operator-facing text lives in `README.md` `bypassRules` comments and the `BypassRule` type comment in `pkg/modsecurity/config.go`. Spec scenarios and tests currently use unanchored patterns that happen to look like prefixes.

## Goals / Non-Goals

**Goals:**

- Make the unanchored contract obvious on every operator-facing surface that describes `pathRegexp`.
- Lock it with one spec scenario set and one unit test.
- Keep compiled matching unchanged.

**Non-Goals:**

- Auto-anchor at compile time.
- Match `RawPath` / `EscapedPath()` or refuse bypass on encoding or `..` mismatch.
- New Config keys.

## Decisions

- **Operator owns anchors.** Wrapping `\A(?:pattern)` would change existing configs that rely on substring match (including README `/healthz` and spec `/search/v1/statement/executing/` prefix-looking patterns that already match suffixes). Alternative considered: auto-prefix `\A`. Rejected by the human.
- **Examples that mean one path include anchors.** README `pathRegexp: /healthz` becomes `^/healthz$`. `^/admin/` stays as a prefix example.
- **Type comment states the matcher**, not just “optional path regexp”.
- **Test locks `/health` vs `/healthz` and `/index.php/health`**, plus `^/health$` vs `/healthz` inspect. That is the documented contract, not a matcher change.
- **Fold** `core_plugin_middleware_bypass-rules`. FindSpecHost: small adjustment to an existing leaf.

## Risks / Trade-offs

- [Operators who copied `/healthz` already skip extra paths] → Docs cannot un-skip those configs. Mitigation: say so clearly; do not silently narrow matching.
- [Spec “contains a match” was already true; a reader might still miss it] → ADDED requirements with substring scenarios, not a silent MODIFIED of the GET executing-path cases.

## Migration Plan

No deploy-time migration. Docs-only plus tests. Rollback is revert the PR.
