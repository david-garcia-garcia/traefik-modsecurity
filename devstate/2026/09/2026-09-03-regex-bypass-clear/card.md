Developer review: in progress — 2026-09-03T07:03:54.794Z

## What this changes
**Operators.** None. (README copy lands at implement.)

**Admin users.** None.

**Developers.** OpenSpec change `bypass-pathregexp-docs` folds `core_plugin_middleware_bypass-rules`: unanchored `pathRegexp` is explicit; the plugin does not insert anchors.

**End users.** None.

## Motivation
On `main`, `bypassRules.pathRegexp` is unanchored RE2 `MatchString` on `req.URL.Path`. README already says that, then shows `pathRegexp: /healthz` without `^` or `$`. The `BypassRule` type comment and spec scenarios still look like prefix allowlists. If we do not merge, an operator can copy that example and skip the WAF for any path that contains the substring.

## Merge readiness
Proposal is apply-ready. README, type comment, and pinning tests are not landed yet.

Priority: P2 — Real operator pain, with a workaround or limited blast radius
Reviewed head: 9517d05
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | OpenSpec ready; CI not seen; implement not started |
| CI proof | 1/6 | Pushed; checks not seen |
| Local tests proof | N/A | Before implement; `prHost` is github |
| Review resolution | 6/6 | OPEN PR; comment inventory empty |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-regex-bypass-clear pushed | `git` (push after this card) |
| OpenSpec | bypass-pathregexp-docs | `openspec/changes/bypass-pathregexp-docs/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/42 | pr-host |
| CI | not seen | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | inventory on PR 42 |
| Security | None. | no codereview.md yet |
| Performance | None. | no codereview.md yet |

## Specs
- [core_plugin_middleware_bypass-rules](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-regex-bypass-clear/openspec/changes/bypass-pathregexp-docs/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local chat spec → branch `2026-09-03-regex-bypass-clear` → PR 42 → OpenSpec `bypass-pathregexp-docs`. Implement next: README, `BypassRule` comment, pinning tests. Matcher stays unanchored.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should match use a normalized path, or refuse bypass when RawPath differs from EscapedPath() or the path contains `.` / `..`? | assumed — no matcher change. Document that the subject is percent-decoded `req.URL.Path` and is not slash-normalized. | explore |

## Before merge
- [ ] Implement README, type comment, and pinning tests
- [x] Stub PR 42 opened
- [x] Explore reproduced unanchored MatchString
- [x] OpenSpec `bypass-pathregexp-docs` apply-ready

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
| Specs in this PR | 0 added / 1 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 9517d05236fbad6991126df25816e9c8fe8efcdb | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Keep MatchString unanchored; make operator docs and spec scenarios say so; pin with tests.

Do we have a high-confidence way to reproduce? Yes. Throwaway `go run` plus existing `bypass.go`.

Is this the best way to solve the issue? Yes versus `main`. Auto-anchor was rejected.

### Evidence
What I checked:
- FindSpecHost fold `core_plugin_middleware_bypass-rules`
- `openspec status --change bypass-pathregexp-docs` 4/4 artifacts complete
- `pkg/modsecurity/bypass.go` still unanchored

### Rank-up moves
None.
