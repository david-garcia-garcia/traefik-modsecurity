Developer review: in progress — 2026-09-03T06:59:42.604Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Motivation
On `main`, `bypassRules.pathRegexp` is unanchored RE2 `MatchString` on `req.URL.Path`. README already says that, then shows `pathRegexp: /healthz` without `^` or `$`. The `BypassRule` type comment and spec scenarios still look like prefix allowlists. If we do not merge, an operator can copy that example and skip the WAF for any path that contains the substring.

## Merge readiness
Explore reproduced the unanchored match and recorded proceed decisions. Product docs are not changed yet.

Priority: P2 — Real operator pain, with a workaround or limited blast radius
Reviewed head: 8b3140a
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Explore written; CI not seen; no product delta versus `main` yet |
| CI proof | 1/6 | Pushed; checks not seen |
| Local tests proof | N/A | Before implement; `prHost` is github |
| Review resolution | 6/6 | OPEN PR; comment inventory empty |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-regex-bypass-clear pushed | `git` / origin |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/42 | pr-host |
| CI | not seen | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | inventory on PR 42 |
| Security | None. | no codereview.md yet |
| Performance | None. | no codereview.md yet |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local chat spec → branch `2026-09-03-regex-bypass-clear` → stub PR 42. Explore: keep unanchored matching; make README, type comment, spec, and one test unambiguous.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should match use a normalized path, or refuse bypass when RawPath differs from EscapedPath() or the path contains `.` / `..`? | assumed — no matcher change. Document that the subject is percent-decoded `req.URL.Path` and is not slash-normalized. | explore |
| Which spec host? | assumed — fold `core_plugin_middleware_bypass-rules`. | explore |
| Is a substring-hit unit test in scope? | assumed — yes, one test so the documented unanchored contract cannot drift. | explore |

## Before merge
- [ ] Propose and land docs/spec so `pathRegexp` cannot be mistaken for prefix matching
- [x] Stub PR 42 opened
- [x] Explore reproduced unanchored MatchString and Path decoding

## Findings
None.

## Agent review details

### Security
None.

### Performance
None.

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 8b3140a29c823c4a9fac73bc919824a70595736d | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Document the existing unanchored contract and make examples carry anchors. Do not rewrite compiled patterns.

Do we have a high-confidence way to reproduce? Yes. Throwaway `go run`: `(?:/health)` matches `/index.php/health` and `/healthz`; `(?:health)` matches `/unhealthy`.

Is this the best way to solve the issue? Yes versus `main`: the human forbade auto-anchor; remaining harm is misleading docs.

### Evidence
What I checked:
- Throwaway `go run` MatchString and `url.Parse` Path/RawPath (temp, not committed)
- `pkg/modsecurity/bypass.go` match on `req.URL.Path`
- README `bypassRules` comments at 242-256
- Existing research `knowledge/research/ext_golang_regexp_alternation/notes.md`

### Rank-up moves
None.
