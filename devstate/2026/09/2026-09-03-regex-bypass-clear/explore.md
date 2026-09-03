# Explore
IssueKey: 2026-09-03-regex-bypass-clear

## Concepts

Operator `pathRegexp` is compiled as `(?:pattern)` and joined with `|`. ServeHTTP matches with `Regexp.MatchString` on `req.URL.Path`. That is substring search. The plugin does not insert `^`, `$`, `\A`, or `\z`.

`req.URL.Path` is the percent-decoded path. Go does not collapse `.` / `..` segments on that field. `%2f` becomes `/` in `Path`; `RawPath` keeps the escaped form when it differs.

README already says MatchString is unanchored and that `^/health$` is exact. The example still shows unanchored `/healthz` beside anchored `^/admin/`. `BypassRule` godoc and spec scenarios still read like prefix allowlists. The implementer usage packet already states the unanchored contract.

```
  operator YAML pathRegexp
           │
           ▼
  compileBypassByMethod  →  (?:pattern) | (?:pattern2)
           │
           ▼
  match(req)  →  MatchString(req.URL.Path)
           │
           ├── hit  →  skip sidecar (bypassrule)
           └── miss →  inspect
```

## Decisions

- Keep unanchored matching. Do not wrap compiled patterns with `\A` or `\z`. The operator writes `^` / `$` (or `\A` / `\z`) when they want prefix or exact.
- Fold onto existing spec `core_plugin_middleware_bypass-rules`. Do not add a new spec id.
- Operator-facing README examples that mean prefix or exact MUST include anchors. Replace `/healthz` with `^/healthz$` (or `^/healthz` if prefix is the intent).
- `BypassRule` type comment must say unanchored `MatchString` on `req.URL.Path` and that anchors are the operator’s.
- Spec: keep “contains a match”. Add a scenario where an unanchored pattern skips a longer or later path (`/health` vs `/healthz` or `/index.php/health`). Do not rewrite existing GET executing-path scenarios unless they currently imply prefix-only.
- Add one unit test that locks the documented unanchored contract (substring hit still bypasses). Do not change matcher code except comments.
- Usage packet `knowledge/devdocs/core_plugin_middleware.md` already states unanchored MatchString. No Language write. No usage rewrite unless implement changes a line that packet still claims.

## Reproduction

Ran a throwaway `go run` against this worktree’s toolchain (temp, not committed).

| Pattern | Path | MatchString |
| --- | --- | --- |
| `(?:/health)` | `/health` | true |
| `(?:/health)` | `/unhealthy` | false (leading slash in the pattern) |
| `(?:health)` | `/unhealthy` | true |
| `(?:/health)` | `/index.php/health` | true |
| `(?:/health)` | `/healthz` | true |
| `(?:/health)` | `/health/../index.php` | true (`Path` keeps `..`) |
| `(?:/health)` | `/health/../admin` from `/health%2f..%2fadmin` | true (`Path` decoded) |

Review trigger `pathRegexp: "/health"` does skip `/index.php/health`, `/healthz`, and the `..` forms. It does not skip `/unhealthy`. README’s `health` (no slash) vs `/unhealthy` example is the accurate unanchored demo.

`url.Parse` for `/health/../index.php`: `Path` stays `/health/../index.php` (not cleaned). For `/health%2f..%2fadmin`: `Path=/health/../admin`, `RawPath=/health%2f..%2fadmin`.

## Open questions

- Q: Should the plugin auto-anchor compiled `pathRegexp` (`\A(?:pattern)`)?
  Decision: resolved — no. Operator prefixes `^` (or `\A`) when they want start-of-path. Human: 2026-09-03.
  By: explore

- Q: Should match use a normalized path, or refuse bypass when `RawPath` differs from `EscapedPath()` or the path contains `.` / `..`?
  Decision: assumed — no matcher change. Document that the subject is percent-decoded `req.URL.Path` and is not slash-normalized. Operator who needs a single cleaned path writes a pattern that matches only that path (typically `^…$`).
  By: explore

- Q: Which spec host?
  Decision: resolved — fold `core_plugin_middleware_bypass-rules` (FindSpecHost small adjustment, confidence high).
  By: propose

- Q: Is a substring-hit unit test in scope?
  Decision: resolved — yes. tasks 1.1–1.2 pin `/health` vs `/healthz` and `/index.php/health`, plus `^/health$` inspects `/healthz`.
  By: propose
