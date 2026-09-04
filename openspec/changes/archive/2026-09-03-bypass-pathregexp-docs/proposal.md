## Why

`bypassRules.pathRegexp` is unanchored RE2 `MatchString` on percent-decoded `req.URL.Path`. Operators can copy a natural-looking pattern such as `/healthz` and skip the WAF for any path that contains that substring. Auto-anchoring would change existing configs; the operator must write `^` / `$` (or `\A` / `\z`). Docs, the type comment, and spec scenarios still look like prefix matching.

## What Changes

- Document that `pathRegexp` is unanchored substring search against `req.URL.Path` (percent-decoded, not slash-normalized).
- Document that prefix or exact matching is the operator’s job (`^…`, `^…$`).
- Replace README examples that omit anchors while implying a single path.
- Spell the same contract on the `BypassRule` type comment.
- Add a spec scenario where an unanchored pattern skips a longer or later path.
- Add one unit test that locks the unanchored contract.
- **Not** wrapping compiled patterns with `\A` / `\z`. **Not** changing the match subject to `RawPath` / `EscapedPath()`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_bypass-rules`: Make unanchored `MatchString` on `req.URL.Path` an explicit requirement, including a substring-hit scenario, and that the plugin SHALL NOT insert anchors into the operator pattern.

## Impact

- `README.md` `bypassRules` comments
- `pkg/modsecurity/config.go` `BypassRule` comment
- `openspec/specs/core_plugin_middleware_bypass-rules/spec.md` (via this change’s delta)
- `pkg/modsecurity/bypass_test.go` (one substring-hit case)
- Matcher in `pkg/modsecurity/bypass.go` stays unanchored `MatchString`
