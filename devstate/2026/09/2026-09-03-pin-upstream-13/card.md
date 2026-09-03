Developer review: in progress — 2026-09-03T04:17:31.164Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Research packet `knowledge/research/ext_authelia_api_firstfactor/` records Authelia POST `/api/firstfactor` as 200/401, not 405. The Authelia-shaped unit test is not on this branch yet.

**End users.** None.

## Motivation
Without this PR, [acouvreur/traefik-modsecurity-plugin#13](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/13) (Authelia login POST 405) has no regression pin in this tree that the plugin does not invent that status.

## Merge readiness
Prepare complete; explore not started. 6 items remain.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: d290bd7
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Stub PR exists; CI still running; test not landed |
| CI proof | 3/6 | Checks queued or in progress on run 33714502710 |
| Local tests proof | N/A | Before implement (`localTests: none`) |
| Review resolution | 6/6 | OPEN PR; no reviewer comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-pin-upstream-13 pushed | `git` / origin |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/36 | pr-host Create |
| CI | build 33714502710 in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33714502710 | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | inventory empty |
| Security | None. | no codereview.md |
| Performance | None. | no codereview.md |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local caller asked for a tests-only pin of upstream Authelia login POST 405. Branch `2026-09-03-pin-upstream-13` opened stub PR 36; next is explore then land `pkg/modsecurity/upstream_issue_13_test.go`.

## Decision needed
None.

## Before merge
- [ ] Land `pkg/modsecurity/upstream_issue_13_test.go` [P3]
- [ ] Wait for CI on PR 36 to succeed
- [ ] Replace WIP title when ready for review

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
| Specs in this PR | none | Same list as ## Specs; do not paste diff --stat |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | d290bd7613a8d0a29b6423995c6f1f3be7e23e6e | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Research-only so far versus `origin/main`; the pin is still the untracked starter test.

Do we have a high-confidence way to reproduce? Yes, in-process httptest on POST `/api/firstfactor` (starter file exists, not committed).

Is this the best way to solve the issue? Yes — tests-only pin matches the caller; no Authelia compose or 405 knob.

### Evidence
What I checked:
- `pkg/modsecurity/serve.go` never writes 405; copies sidecar 3xx/4xx (`git` HEAD d290bd7)
- Starter `pkg/modsecurity/upstream_issue_13_test.go` matches `New` / `ForRoute` / `NewLogger` on this tree
- Authelia OpenAPI documents POST `/api/firstfactor` 200/401 (`knowledge/research/ext_authelia_api_firstfactor/`)
- Stub PR 36 created; checks in progress (run 33714502710)

### Rank-up moves
None.
