Developer review: ready for review — 2026-09-03T04:36:52.963Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** `pkg/modsecurity/upstream_issue_13_test.go` pins Authelia-shaped `POST /api/firstfactor`: allow is `next` (not 405); sidecar 405 is copied. Those scenarios now live on baseline sidecar-response and sidecar-request.

**End users.** None.

## Motivation
Without this PR, [acouvreur/traefik-modsecurity-plugin#13](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/13) (Authelia login POST 405) has no regression pin that this plugin does not invent that status.

## Merge readiness
OPEN PR, CI succeeded, no open comments. 0 items remain.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: 5d82961
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | All required checks succeeded on head 5d82961 |
| Local tests proof | N/A | Remote PR; localTests passed |
| Review resolution | 6/6 | OPEN PR; no reviewer comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-pin-upstream-13 pushed | `git` / origin |
| OpenSpec | pin-upstream-authelia-405 (archived) | `openspec/changes/archive/2026-09-03-pin-upstream-authelia-405/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/36 | pr-host |
| CI | build 33715062759 success https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33715062759 | pr-host CI (also lint 33715062653, Build 33715062705, go test 33715062741 — all success) |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | inventory empty |
| Security | None. | devstate/codereview.md |
| Performance | None. | devstate/codereview.md |

## Specs
- [core_plugin_middleware_sidecar-response](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-pin-upstream-13/openspec/changes/archive/2026-09-03-pin-upstream-authelia-405/proposal.md) — modified
- [core_plugin_middleware_sidecar-request](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-pin-upstream-13/openspec/changes/archive/2026-09-03-pin-upstream-authelia-405/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local caller asked for a tests-only pin of [acouvreur/traefik-modsecurity-plugin#13](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/13). Branch `2026-09-03-pin-upstream-13` is PR 36; CI succeeded.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Who already owns inbound Host, leftover X-Forwarded-For, and X-Real-Ip on the sidecar request? | assumed — Host owner is Go Request.Host (inbound). XFF / X-Real-Ip owner is Traefik forwarded-headers. | explore |
| Should the issue-13 fixture use Authelia's official JSON body instead of form-urlencoded? | assumed — keep the starter form body. | explore |
| New spec leaf vs fold into sidecar-response / sidecar-request? | assumed — fold. Archived onto those baseline specs. | archive |
| Does build_testing_go need a usage update for upstream_issue_*_test.go? | assumed — yes; Key files line landed. | implement |

## Before merge
None.

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
| Reviewed head | 5d82961fe08d1a519dcc387f75482e99ef67f423 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Unit pin versus `origin/main` that this plugin does not invent 405 on Authelia login POST.

Do we have a high-confidence way to reproduce? Yes — `TestPlugin_UpstreamIssue13_PostFirstFactorNeverEmits405` passed locally and in CI.

Is this the best way to solve the issue? Yes — tests only; no Authelia compose or 405 knob.

### Evidence
What I checked:
- Check runs on PR 36 head 5d82961: lint, Build, build, Test Runner Script Validation, Integration Tests (nginx), Integration Tests (apache) — all success
- Local `go test ./...` passed (race unavailable: CGO off)

### Rank-up moves
None.
