Developer review: in progress — 2026-09-03T07:35:17.109Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** `readInboundBody` copies pooled body bytes into an owned slice and Puts the buffer before `ServeHTTP` builds sidecar/`next` readers. `TestPlugin_PooledBodyNotAliasedAfterPut` fails without that copy (1 MiB `0xAA` overwritten by `0xBB`) and passes with it.

**End users.** None.

## Motivation
On `main`, Put of a pooled body buffer can overwrite another tenant's POST while the sidecar still reads the aliased bytes. Without this PR that leak stays in production.

## Merge readiness
Copy-out and reproducing test are on the branch. Archive and CI wait remain.

Priority: P1 — Production is unsafe, losing data, or serving a wrong public contract today
Reviewed head: 53789d3
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Local tests passed; CI not seen on this head |
| CI proof | 1/6 | not seen on 53789d3 |
| Local tests proof | N/A | Remote PR; CI proof covers this |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-pooled-body-race pushed | `git` 53789d3 |
| OpenSpec | pooled-body-alias-copy-out | `openspec/changes/pooled-body-alias-copy-out/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/44 | pr-host |
| CI | not seen | check_runs empty immediately after push |
| Local tests | passed | `go test -count=1 ./...` ok; leak test FAIL then PASS |
| PR comments | no comments | inventory empty |
| Security | None. | no codereview.md yet |
| Performance | None. | no codereview.md yet |

## Specs
- [core_plugin_middleware_body-pool](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-pooled-body-race/openspec/changes/pooled-body-alias-copy-out/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
PR 44. Task 1.2 FAIL recorded (`0xAA=0 0xBB=1048576`), then copy-out, then the same test PASS. Next is four-axis review, archive, CI wait.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Copy-out or wait until the sidecar body is consumed? | assumed — copy-out before any transport owns the slice. | explore |
| Should the regression test use a real `http.Transport` 403-without-read? | assumed — no. Use a RoundTripper that holds Body until after Put. | explore |
| Who already owns client address, user, tenant, Host, or trust hop for this change? | assumed — none. | explore |
| Local `go test -race` on this Windows agent? | assumed — not available (`CGO_ENABLED=0`). Semantic leak test is the local proof. | explore |

## Before merge
- [ ] Wait for CI on PR 44 including `go test -race`
- [x] Stub PR 44 opened
- [x] Leak test FAIL then copy-out then PASS
- [x] OpenSpec change apply-ready

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
| Specs in this PR | 0 added / 1 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 53789d3bba5517a75e9a6d5974be902fbf5f95d4 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: copy `buf.Bytes()` then Put inside `readInboundBody` so transports never alias the pool.

Do we have a high-confidence way to reproduce? Yes. `TestPlugin_PooledBodyNotAliasedAfterPut` failed with a full 1 MiB `0xBB` leak, then passed after copy-out.

Is this the best way to solve the issue? Yes vs DestBranch. Waiting on Close does not match writeLoop.

### Evidence
What I checked:
- FAIL `go test ... -run TestPlugin_PooledBodyNotAliasedAfterPut` — `0xAA=0 0xBB=1048576` (commit f6be5ac, before copy-out)
- PASS same test after `body.go` copy-out (8cb2f4b)
- `go test -count=1 ./...` passed
- CI not seen on 53789d3

### Rank-up moves
None.
