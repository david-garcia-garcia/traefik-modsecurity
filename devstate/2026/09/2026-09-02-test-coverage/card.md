Developer review: in progress — 2026-09-02T19:10:09Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Prepare only: requirement grounded for `2026-09-02-test-coverage`. No test or plugin files changed versus `main`.

**End users.** None.

## Motivation
`origin/main` already covers most of the `report.md` enforcement-path holes (websocket handshake vs forged Upgrade, sidecar 5xx/3xx, fail-open, Host/XFF, deny-verbs-with-body, connection reuse, inbound cancel, and several `Prepare` validations). Without this PR, three weaker spots stay: two `TestModsecurity_ServeHTTP` rows still share one `*http.Request`, there is no parallel mixed-body `ServeHTTP` race guard (CI does not pass `-race`), and `config_test.go` does not exercise every `rejectNegative` field.

## Merge readiness
Prepare complete; explore has not started. Remaining work is to confirm the leftover holes and add only those tests.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: 8c6037c
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Stub PR is open; CI is still running; no product tests landed yet |
| CI proof | 3/6 | Checks in progress on PR 30 |
| Local tests proof | N/A | Before implement (`localTests: none`) |
| Review resolution | 6/6 | New PR, no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-02-test-coverage pushed | `origin/2026-09-02-test-coverage` |
| OpenSpec | none | no change folder |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/30 | pr-host Create |
| CI | in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33671619748 | Integration Tests nginx/apache, lint, Build, build, Test Runner Script Validation |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | pull_request_read get_comments / get_review_comments |
| Security | None. | no codereview.md |
| Performance | None. | no codereview.md |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local spec from `report.md` lines 149–161 on branch `2026-09-02-test-coverage` (worktree `traefik-modsecurity-plugin-test-coverage`), stub PR 30 into `main`. Qualify is `qualified-with-gaps` because most listed holes are already closed on `origin/main`.

## Decision needed
None.

## Before merge
- [ ] Explore remaining holes versus `origin/main` (clone the two shared-request rows; zero-window ServeHTTP; leftover `rejectNegative` fields; mixed-body `-race` / CI)
- [ ] Implement only tests that are still missing

## Findings
- [P3] Report vs `origin/main` — most of the ten listed holes already have tests on `727d1e7`. Path: `modsecurity_test.go`, `pkg/modsecurity/serve_test.go`, `deny_verbs_with_body_test.go`, `pkg/modsecurity/config_test.go`. Reply none.

## Agent review details

### Security
None.

### Performance
None.

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | No spec.md in the delta |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | New stub PR |
| Reviewed head | 8c6037c082763a9aa3245d076a66e72311361316 | Matches pushed IssueKey |

### Stored data model
None.

### Technical review
Best possible solution: Ground remaining test work against `origin/main` instead of re-adding coverage that already landed.

Do we have a high-confidence way to reproduce? Yes, the leftover shared `req` rows in `TestModsecurity_ServeHTTP` and the missing parallel mixed-body test are visible in the tree.

Is this the best way to solve the issue? Yes — close only the holes that remain versus `DestBranch`.

### Evidence
What I checked:
- `origin/main` at `727d1e7` test files listed above (worktree checkout)
- PR 30 comments empty; six checks in progress
- Qualify `qualified-with-gaps`

### Rank-up moves
None.
