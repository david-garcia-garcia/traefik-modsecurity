Developer review: in progress — 2026-09-03T07:08:13.126Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Motivation
On `main`, `readInboundBody` returns a slice that aliases a pooled `bytes.Buffer`, and `ServeHTTP` Puts that buffer when the handler returns. The sidecar `http.Client` (and `next`) can still be reading those bytes. A later request can reuse the same buffer and overwrite another tenant's POST, including onto the WAF connection. Without this PR that leak stays untested and unfixed.

## Merge readiness
Grounded and qualified; product fix not started. 7 items remain.

Priority: P1 — Production is unsafe, losing data, or serving a wrong public contract today
Reviewed head: a52b9e9
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI still running; no product change yet |
| CI proof | 3/6 | Checks in progress on PR 44 |
| Local tests proof | N/A | Before implement |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-pooled-body-race pushed | `git` origin/2026-09-03-pooled-body-race a52b9e9 |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/44 | pr-host Create |
| CI | build 33726484802 in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33726484802 | pr-host check_runs: Build success, Test Runner Script Validation success, lint/build/integration in progress |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | inventory empty |
| Security | None. | no codereview.md yet |
| Performance | None. | no codereview.md yet |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Chat finding 3 became local ticket `2026-09-03-pooled-body-race` on a dedicated worktree, stub PR 44 against `main`. Next is explore, then a reproducing test, then the pool-alias fix.

## Decision needed
None.

## Before merge
- [ ] [P1] Record a test that fails on current `main` by reproducing cross-request body bytes or the race, then land the production fix that stops the pooled array escaping into `net/http`
- [x] Stub PR 44 opened

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
| Reviewed head | a52b9e9017ed749319bbe596c563334a3b5ba99b | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: not chosen yet; requirement is copy-out or wait-until-consumed so Put cannot race a live transport reader.

Do we have a high-confidence way to reproduce? Not yet. Existing `TestPlugin_ConcurrentMixedBodySizesDoNotRace` drains the WAF body and uses 200/4096-byte payloads.

Is this the best way to solve the issue? Not decided. Explore will pick copy-out vs wait.

### Evidence
What I checked:
- `pkg/modsecurity/body.go:48-59` returns `buf.Bytes()` plus a Put `release` (worktree HEAD a52b9e9)
- `pkg/modsecurity/serve.go:54-70` defers Put and aliases the same slice into two `bytes.NewReader`s
- `pkg/modsecurity/body_pool_test.go` concurrent test ReadAlls the sidecar body
- PR 44 created; comments empty; CI in progress (run 33726484802)

### Rank-up moves
None.
