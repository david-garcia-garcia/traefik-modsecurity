Developer review: in progress — 2026-09-03T06:56:13.557Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Motivation
On `main`, `bypassRules.pathRegexp` is unanchored RE2 `MatchString` on `req.URL.Path`. README already says that, then shows `pathRegexp: /healthz` without `^` or `$`. The `BypassRule` type comment and spec scenarios still look like prefix allowlists. If we do not merge, an operator can copy that example and skip the WAF for any path that contains the substring.

## Merge readiness
Prepare grounded the ticket and opened the stub PR. Product docs and spec are not changed yet.

Priority: P2 — Real operator pain, with a workaround or limited blast radius
Reviewed head: 8ee9769
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Stub PR exists; CI not seen; no product delta versus `main` yet |
| CI proof | 1/6 | Pushed; checks not seen |
| Local tests proof | N/A | Before implement; `prHost` is github |
| Review resolution | 6/6 | OPEN PR; comment inventory empty |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-regex-bypass-clear pushed | `git` / origin |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/42 | pr-host Create |
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
Local chat spec → branch `2026-09-03-regex-bypass-clear` from `main` in worktree `wt-modsec-2026-09-03-regex-bypass-clear` → stub PR 42. Next is explore: keep unanchored matching, make operator docs unambiguous.

## Decision needed
None.

## Before merge
- [ ] Explore, propose, and land docs/spec so `pathRegexp` cannot be mistaken for prefix matching
- [x] Stub PR 42 opened

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
| Reviewed head | 8ee976964b49de4792d8978d9decd9173be1dde7 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not started versus `main`; this card is prepare only.

Do we have a high-confidence way to reproduce? Yes, `MatchString` on `req.URL.Path` is in `pkg/modsecurity/bypass.go`.

Is this the best way to solve the issue? Not decided in prepare. Human already ruled out auto-anchoring.

### Evidence
What I checked:
- `origin/main` at 342d3cf (git fetch)
- `compiledBypass.match` uses unanchored `MatchString` (`pkg/modsecurity/bypass.go`)
- README `bypassRules` comments already mention unanchored MatchString and still example `/healthz`
- PR 42 created; issue and review comments empty

### Rank-up moves
None.
