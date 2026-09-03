Developer review: in progress — 2026-09-03T07:29:14.361Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** OpenSpec change `pooled-body-alias-copy-out` folds a copy-out requirement into `core_plugin_middleware_body-pool`. Production copy-out is not landed yet.

**End users.** None.

## Motivation
On `main`, Put of a pooled body buffer can overwrite another request's POST while the sidecar still reads the aliased bytes. Without this PR that leak stays untested and unfixed.

## Merge readiness
Proposal is apply-ready. Failing test and copy-out not started. 5 items remain.

Priority: P1 — Production is unsafe, losing data, or serving a wrong public contract today
Reviewed head: 3374ac4
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Pushed; CI not seen on this head yet |
| CI proof | 1/6 | not seen on 3374ac4 |
| Local tests proof | N/A | Before implement |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-pooled-body-race pushed | after this card's push |
| OpenSpec | pooled-body-alias-copy-out | `openspec/changes/pooled-body-alias-copy-out/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/44 | pr-host |
| CI | not seen | not measured on 3374ac4 before push |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | inventory empty |
| Security | None. | no codereview.md yet |
| Performance | None. | no codereview.md yet |

## Specs
- [core_plugin_middleware_body-pool](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-pooled-body-race/openspec/changes/pooled-body-alias-copy-out/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
PR 44. Change `pooled-body-alias-copy-out` is apply-ready. Implement must record a FAIL on `TestPlugin_PooledBodyNotAliasedAfterPut` before copy-out.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Copy-out or wait until the sidecar body is consumed? | assumed — copy-out before any transport owns the slice. | explore |
| Should the regression test use a real `http.Transport` 403-without-read? | assumed — no. Use a RoundTripper that holds Body until after Put. | explore |
| Who already owns client address, user, tenant, Host, or trust hop for this change? | assumed — none. | explore |
| Local `go test -race` on this Windows agent? | assumed — not available (`CGO_ENABLED=0`). Semantic leak test is the local proof. | explore |

## Before merge
- [ ] [P1] Land the failing leak test, then copy-out, then confirm the same test passes
- [x] Stub PR 44 opened
- [x] Leak reproduced (explore throwaway)
- [x] OpenSpec change `pooled-body-alias-copy-out` apply-ready

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
| Reviewed head | 3374ac4cbdd62fd8390a39a1a69b10b5c5446091 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: copy `buf.Bytes()` into an owned slice, Put, then hand the copy to sidecar and `next`.

Do we have a high-confidence way to reproduce? Yes. Explore throwaway: 1 MiB `0xBB` leak after Put.

Is this the best way to solve the issue? Yes vs DestBranch. Waiting on Close does not match writeLoop.

### Evidence
What I checked:
- `openspec validate pooled-body-alias-copy-out --type change --strict` valid
- FindSpecHost fold `core_plugin_middleware_body-pool` high
- Explore FAIL `0xAA=0 0xBB=1048576`

### Rank-up moves
None.
