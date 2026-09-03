Developer review: in progress — 2026-09-03T07:10:56.601Z

## What this changes
**Operators.** `bypassRules.pathRegexp` comments now say unanchored `MatchString` on percent-decoded `req.URL.Path`. Exact example is `^/healthz$`. Prefix example stays `^/admin/`. The plugin still does not insert those anchors.

**Admin users.** None.

**Developers.** `BypassRule` and `match` comments spell the unanchored contract. `TestPlugin_BypassRules` pins `/health` vs `/healthz`, `/index.php/health`, `^/health$`, and `/health/../index.php`.

**End users.** None.

## Motivation
On `main`, `bypassRules.pathRegexp` is unanchored RE2 `MatchString` on `req.URL.Path`. README already said that, then showed `pathRegexp: /healthz` without `^` or `$`. The `BypassRule` type comment and spec scenarios still looked like prefix allowlists. If we do not merge, an operator can copy that example and skip the WAF for any path that contains the substring.

## Merge readiness
Apply landed. Four-axis review of `origin/main...HEAD` was clean (Standards / Spec / Security / Performance: none). CI on PR 42 is still running.

Priority: P2 — Real operator pain, with a workaround or limited blast radius
Reviewed head: e5ea6df
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Local `go test ./...` passed; CI in progress |
| CI proof | 3/6 | Checks queued/in_progress on 8d625f9 |
| Local tests proof | N/A | `prHost` is github |
| Review resolution | 6/6 | OPEN PR; comment inventory empty |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-regex-bypass-clear pushed | `git` / origin |
| OpenSpec | bypass-pathregexp-docs | `openspec/changes/bypass-pathregexp-docs/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/42 | pr-host |
| CI | build 33726489907 in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33726489907 | pr-host check_runs |
| Local tests | passed | `go test ./...` ok |
| PR comments | no comments | inventory on PR 42 |
| Security | None. | devstate/codereview.md |
| Performance | None. | devstate/codereview.md |

## Specs
- [core_plugin_middleware_bypass-rules](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-regex-bypass-clear/openspec/changes/bypass-pathregexp-docs/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local chat spec → branch `2026-09-03-regex-bypass-clear` → PR 42 → OpenSpec `bypass-pathregexp-docs` applied. Four-axis review clean. Waiting on CI.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should match use a normalized path, or refuse bypass when RawPath differs from EscapedPath() or the path contains `.` / `..`? | assumed — no matcher change. Document that the subject is percent-decoded `req.URL.Path` and is not slash-normalized. | explore |

## Before merge
- [ ] CI succeeded on PR 42
- [x] README, type comment, and pinning tests landed
- [x] Stub PR 42 opened
- [x] OpenSpec `bypass-pathregexp-docs` applied
- [x] Four-axis review of origin/main...HEAD was clean

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
| Reviewed head | e5ea6df59454aaa0048dc537c480dbfeaba75587 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Keep MatchString unanchored; make operator docs and examples carry anchors; pin with tests.

Do we have a high-confidence way to reproduce? Yes. `go test ./pkg/modsecurity -run TestPlugin_BypassRules` passed including substring cases.

Is this the best way to solve the issue? Yes versus `main`. Auto-anchor was rejected.

### Evidence
What I checked:
- `go test ./...` passed (health, modsecurity, reclaim, root)
- `bypass.go` still wraps `(?:pattern)` only
- README example is `^/healthz$`
- Four-axis review: Standards/Spec/Security/Performance none (origin/main...HEAD)

### Rank-up moves
None.
