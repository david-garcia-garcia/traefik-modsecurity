Developer review: in progress — 2026-09-02T19:13:57Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Explore only: remaining holes are shared `req` in `TestModsecurity_ServeHTTP`, missing `rejectNegative` cases, and no concurrent mixed-body `ServeHTTP` under `-race`. Zero-window ServeHTTP is not reachable after `Prepare`.

**End users.** None.

## Motivation
Without this PR, `TestModsecurity_ServeHTTP` can still pass while two rows share one `*http.Request`, `Prepare` negatives besides timeout/body size stay untested, and the body-pool alias of `buf.Bytes()` has no concurrent mixed-size race guard in CI.

## Merge readiness
Explore written; propose and tests have not started. Apache integration on PR 30 is still running.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: 2778b2e
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Explore done; CI still has one in-progress job; no product tests landed |
| CI proof | 3/6 | Five checks succeeded; Integration Tests (apache) in progress |
| Local tests proof | N/A | Before implement |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-02-test-coverage pushed | origin |
| OpenSpec | none | no change folder yet |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/30 | pr-host |
| CI | in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33671779217 | apache still running; others success |
| Local tests | none | handoff.yaml |
| PR comments | no comments | inventory |
| Security | None. | no codereview.md |
| Performance | None. | no codereview.md |

## Specs
None.

## Follow-up issues
None.

## How this fits together
`TestModsecurity_ServeHTTP` was run and passed (`go test -count=1 -run TestModsecurity_ServeHTTP$`) despite two rows sharing `req`. Explore decided clone those rows, add remaining `rejectNegative` tests, add concurrent mixed-body ServeHTTP, and pass `-race` on `go.yml` only.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should CI gain `-race`, or only a unit test? | assumed — concurrent mixed-body test plus `-race` on `.github/workflows/go.yml` Test only; `build.yml` stays without `-race` | explore |
| Will sibling worktrees add these tests first? | assumed — ignore sibling trees; close holes on this branch against `origin/main` | explore |

## Before merge
- [ ] Propose and implement the remaining tests
- [ ] Wait for CI on the test commits

## Findings
- [P3] Shared `req` contamination still present — `TestModsecurity_ServeHTTP` PASS 2026-09-02. Path: `modsecurity_test.go` rows that pass `request: req`. Reply none.

## Agent review details

### Security
None.

### Performance
None.

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Explore; no OpenSpec change yet |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | New stub PR |
| Reviewed head | 2778b2ed33e5fba81e33a0b4b3d663576a0ed75a | Pre-explore commit |

### Stored data model
None.

### Technical review
Best possible solution: Close only the holes still missing on `origin/main`.

Do we have a high-confidence way to reproduce? Yes, `TestModsecurity_ServeHTTP` still passes with shared `req`.

Is this the best way to solve the issue? Yes — tests and `go.yml -race`, not product behavior changes.

### Evidence
What I checked:
- `go test -count=1 -run TestModsecurity_ServeHTTP$` PASS
- `Prepare` maps window 0 → 10 (`pkg/modsecurity/config.go`)
- `health.New` window 0 covered in `pkg/health/tracker_test.go`

### Rank-up moves
None.
