Developer review: in progress — 2026-09-03T04:24:01.916Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** `pkg/modsecurity/upstream_issue_13_test.go` pins Authelia-shaped `POST /api/firstfactor`: allow is `next` (not 405); sidecar 405 is copied. OpenSpec `pin-upstream-authelia-405` folds those scenarios onto sidecar-response and sidecar-request.

**End users.** None.

## Motivation
Without this PR, [acouvreur/traefik-modsecurity-plugin#13](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/13) (Authelia login POST 405) has no regression pin that this plugin does not invent that status.

## Merge readiness
Test landed; CI still queued. 2 items remain.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: 8770180
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Apply landed; CI queued on the implement head |
| CI proof | 3/6 | Checks queued on run 33714903453 |
| Local tests proof | N/A | Remote PR; local `go test ./...` passed (no race here) |
| Review resolution | 6/6 | OPEN PR; no reviewer comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-pin-upstream-13 pushed | `git` / origin |
| OpenSpec | pin-upstream-authelia-405 | `openspec/changes/pin-upstream-authelia-405/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/36 | pr-host |
| CI | build 33714903453 in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33714903453 | pr-host CI |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | inventory empty |
| Security | None. | no codereview.md yet |
| Performance | None. | no codereview.md yet |

## Specs
- [core_plugin_middleware_sidecar-response](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-pin-upstream-13/openspec/changes/pin-upstream-authelia-405/proposal.md) — modified
- [core_plugin_middleware_sidecar-request](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-pin-upstream-13/openspec/changes/pin-upstream-authelia-405/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local caller asked for a tests-only pin of upstream Authelia login POST 405. The unit test is on PR 36. Next: four-axis review, then CI wait at pullrequest.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Who already owns inbound Host, leftover X-Forwarded-For, and X-Real-Ip on the sidecar request? | assumed — Host owner is Go Request.Host (inbound). XFF / X-Real-Ip owner is Traefik's entrypoint forwarded-headers wrapper (copied as-is). This plugin does not reconstruct those facts from RemoteAddr. | explore |
| Should the issue-13 fixture use Authelia's official JSON body instead of form-urlencoded? | assumed — keep the starter form body. The test pins plugin status/header copy, not Authelia parsing. | explore |
| New spec leaf vs fold into sidecar-response / sidecar-request? | assumed — fold. Add a 405-copy scenario on sidecar-response and an Authelia-shaped POST scenario on sidecar-request. No new 4th part; no Authelia domain. | propose |
| Does build_testing_go need a usage update for upstream_issue_*_test.go? | assumed — yes, one Key files line at implement/devdocsimpact if the file lands. No new Language term. | implement |

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
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs; do not paste diff --stat |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 87701800e77d27487482e75cd9e8c263bea712bd | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Unit pin versus `origin/main` with no runtime change.

Do we have a high-confidence way to reproduce? Yes — `TestPlugin_UpstreamIssue13_PostFirstFactorNeverEmits405` passed locally.

Is this the best way to solve the issue? Yes — tests-only pin; plugin does not invent 405.

### Evidence
What I checked:
- `go test ./pkg/modsecurity/ -run TestPlugin_UpstreamIssue13_PostFirstFactorNeverEmits405` pass
- `go test ./...` pass (race detector unavailable locally: CGO off)
- Tasks 1.1, 1.2, 2.1 checked

### Rank-up moves
None.
