Developer review: in progress — 2026-09-03T04:24:56.421Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** `pkg/modsecurity/upstream_issue_13_test.go` pins Authelia-shaped `POST /api/firstfactor`: allow is `next` (not 405); sidecar 405 is copied. Four-axis review of `origin/main...HEAD` found no hard issues.

**End users.** None.

## Motivation
Without this PR, [acouvreur/traefik-modsecurity-plugin#13](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/13) (Authelia login POST 405) has no regression pin that this plugin does not invent that status.

## Merge readiness
Code review clean; CI not re-measured this card. 2 items remain.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: 153a4f8
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Review clean; CI still in flight on later heads |
| CI proof | 3/6 | Implement-head checks were queued; this bus commit just created |
| Local tests proof | N/A | Remote PR; localTests passed |
| Review resolution | 6/6 | OPEN PR; no reviewer comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-pin-upstream-13 pushed | `git` / origin |
| OpenSpec | pin-upstream-authelia-405 | `openspec/changes/pin-upstream-authelia-405/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/36 | pr-host |
| CI | not seen | bus commit 153a4f8 after implement push |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | inventory empty |
| Security | None. | devstate/codereview.md |
| Performance | None. | devstate/codereview.md |

## Specs
- [core_plugin_middleware_sidecar-response](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-pin-upstream-13/openspec/changes/pin-upstream-authelia-405/proposal.md) — modified
- [core_plugin_middleware_sidecar-request](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-pin-upstream-13/openspec/changes/pin-upstream-authelia-405/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Tests-only pin of [acouvreur/traefik-modsecurity-plugin#13](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/13) is on PR 36. Four-axis review is clean. Next: usage-doc impact, archive, then wait for CI.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Who already owns inbound Host, leftover X-Forwarded-For, and X-Real-Ip on the sidecar request? | assumed — Host owner is Go Request.Host (inbound). XFF / X-Real-Ip owner is Traefik's entrypoint forwarded-headers wrapper (copied as-is). This plugin does not reconstruct those facts from RemoteAddr. | explore |
| Should the issue-13 fixture use Authelia's official JSON body instead of form-urlencoded? | assumed — keep the starter form body. The test pins plugin status/header copy, not Authelia parsing. | explore |
| New spec leaf vs fold into sidecar-response / sidecar-request? | assumed — fold. | propose |
| Does build_testing_go need a usage update for upstream_issue_*_test.go? | assumed — yes; Key files line landed. | implement |

## Before merge
- [x] Land `pkg/modsecurity/upstream_issue_13_test.go` [P3]
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
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 153a4f86a28fe15796ef542f057e57684bc7d273 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Unit pin versus `origin/main`; no runtime change.

Do we have a high-confidence way to reproduce? Yes — dedicated unit test passed.

Is this the best way to solve the issue? Yes.

### Evidence
What I checked:
- Four-axis review of `origin/main...HEAD` excluding `devstate/` (codereview.md)
- Local `go test ./...` passed

### Rank-up moves
None.
