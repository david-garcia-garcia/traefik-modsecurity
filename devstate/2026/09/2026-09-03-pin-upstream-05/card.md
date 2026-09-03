Developer review: in progress — 2026-09-03T04:15:54Z

Upstream: [acouvreur/traefik-modsecurity-plugin#5](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/5)

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None yet versus `main`. This branch has an empty start commit and the run bus only. Starter tests in `pkg/modsecurity/upstream_issue_05_test.go` are still untracked.

**End users.** None.

## Motivation
Without this PR, [acouvreur/traefik-modsecurity-plugin#5](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/5) (HTTP/2 abort / Yaegi panic blamed on `isWebsocket`) has no regression tests on this plugin. A later change could reintroduce a panic with no failing test.

## Merge readiness
Prepare finished; tests not landed. Remaining phases plus landing the starter file.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: e7b6fb7
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Pushed; CI not seen yet |
| CI proof | 1/6 | Pushed and still not seen |
| Local tests proof | N/A | Before implement (`localTests: none`) |
| Review resolution | 6/6 | OPEN PR; no reviewer comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-pin-upstream-05 pushed | `git` tracking `origin/2026-09-03-pin-upstream-05` |
| OpenSpec | none | `openspec/changes/` empty for this change |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/32 | pr-host Create |
| CI | not seen | adapter after stub open |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | inventory empty |
| Security | None. | no codereview.md yet |
| Performance | None. | no codereview.md yet |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local ticket `2026-09-03-pin-upstream-05` opened stub PR #32 against `main` so later cards can live on the PR summary. Next is explore, then land the starter tests.

## Decision needed
None.

## Before merge
- [ ] Land `pkg/modsecurity/upstream_issue_05_test.go` (tests only; no `recover` in ServeHTTP)
- [x] Stub PR #32 opened

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
| Specs in this PR | none | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | e7b6fb77d71c25a888c0a065e643d9aae384aace | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: versus `main`, pin the #5 panic with tests only; do not change ServeHTTP.

Do we have a high-confidence way to reproduce? Not yet — starter tests not run.

Is this the best way to solve the issue? Yes — the ticket asked for coverage, not a product change.

### Evidence
What I checked:
- Branch at `2f39486` matches `origin/main` plus start + run-bus commits (`git`)
- Starter test helpers match `New` / `ForRoute` / `CreateConfig` (`pkg/modsecurity`)
- No `recover` in product ServeHTTP (`pkg/modsecurity/serve.go`)
- Qualify `qualified` (`handoff.yaml`)

### Rank-up moves
None.
