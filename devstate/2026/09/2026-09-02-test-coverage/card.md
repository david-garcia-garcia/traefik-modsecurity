Developer review: in progress — 2026-09-02T19:17:01Z

## What this changes
**Operators.** None. (`go.yml` Test will use `-race` after implement; not landed yet.)

**Admin users.** None.

**Developers.** OpenSpec change `close-remaining-waf-test-gaps` is apply-ready: clone shared `TestModsecurity_ServeHTTP` rows, remaining `Prepare` negatives, concurrent mixed-body `ServeHTTP`, `go.yml` `-race`.

**End users.** None.

## Motivation
Without this PR, two table rows still share one `*http.Request`, several `rejectNegative` fields have no test, and the body-pool alias has no concurrent mixed-size race guard in CI.

## Merge readiness
Propose complete; tests not implemented yet.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: 04ac1f8
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Apply-ready OpenSpec; no product tests landed |
| CI proof | 3/6 | Latest push not re-measured this card |
| Local tests proof | N/A | Before implement |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-02-test-coverage pushed | origin |
| OpenSpec | close-remaining-waf-test-gaps | `openspec/changes/close-remaining-waf-test-gaps/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/30 | pr-host |
| CI | not seen | new propose commit pending |
| Local tests | none | handoff.yaml |
| PR comments | no comments | inventory |
| Security | None. | no codereview.md |
| Performance | None. | no codereview.md |

## Specs
- [build_ci_github_go-test](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-02-test-coverage/openspec/changes/close-remaining-waf-test-gaps/proposal.md) — added
- [core_plugin_middleware_prepare-validation](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-02-test-coverage/openspec/changes/close-remaining-waf-test-gaps/proposal.md) — modified
- [core_plugin_middleware_body-pool](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-02-test-coverage/openspec/changes/close-remaining-waf-test-gaps/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Change `close-remaining-waf-test-gaps` on PR 30. `openspec validate close-remaining-waf-test-gaps --type change --strict` passed.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should CI gain `-race`, or only a unit test? | assumed — concurrent mixed-body test plus `-race` on `.github/workflows/go.yml` Test only; `build.yml` stays without `-race` | explore |
| Will sibling worktrees add these tests first? | assumed — ignore sibling trees; close holes on this branch against `origin/main` | explore |

## Before merge
- [ ] Implement the four tasks
- [ ] Wait for CI on the test commits

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
| Specs in this PR | 1 added / 2 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | No comments |
| Reviewed head | 04ac1f8 (pre-propose OpenSpec commit) | Propose artifacts uncommitted at card write |

### Stored data model
None.

### Technical review
Best possible solution: Tests and `go.yml -race` against `origin/main`, no runtime change.

Do we have a high-confidence way to reproduce? Yes.

Is this the best way to solve the issue? Yes.

### Evidence
What I checked:
- `openspec validate close-remaining-waf-test-gaps --type change --strict` passed
- FindSpecHost fold prepare-validation and body-pool; new `build_ci_github_go-test`

### Rank-up moves
None.
