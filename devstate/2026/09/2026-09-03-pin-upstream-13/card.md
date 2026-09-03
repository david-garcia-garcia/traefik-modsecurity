Developer review: in progress — 2026-09-03T04:18:57.534Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Research packet `knowledge/research/ext_authelia_api_firstfactor/` records Authelia POST `/api/firstfactor` as 200/401, not 405. The Authelia-shaped unit test is not committed yet.

**End users.** None.

## Motivation
Without this PR, [acouvreur/traefik-modsecurity-plugin#13](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/13) (Authelia login POST 405) has no committed regression pin that this plugin does not invent that status.

## Merge readiness
Explore complete; propose not started. 5 items remain.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: 6fe0e7c
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Explore done; CI still running; test not landed |
| CI proof | 3/6 | New checks queued after prepare-close push (run 33714562815) |
| Local tests proof | N/A | Before implement (`localTests: none`) |
| Review resolution | 6/6 | OPEN PR; no reviewer comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-pin-upstream-13 pushed | `git` / origin |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/36 | pr-host |
| CI | build 33714562815 in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33714562815 | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | inventory empty |
| Security | None. | no codereview.md |
| Performance | None. | no codereview.md |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local caller asked for a tests-only pin of upstream Authelia login POST 405. Explore measured the starter test pass (plugin does not invent 405). Next: propose fold into sidecar-response / sidecar-request, then land the test.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Who already owns inbound Host, leftover X-Forwarded-For, and X-Real-Ip on the sidecar request? | assumed — Host owner is Go Request.Host (inbound). XFF / X-Real-Ip owner is Traefik's entrypoint forwarded-headers wrapper (copied as-is). This plugin does not reconstruct those facts from RemoteAddr. | explore |
| Should the issue-13 fixture use Authelia's official JSON body instead of form-urlencoded? | assumed — keep the starter form body. The test pins plugin status/header copy, not Authelia parsing. | explore |
| New spec leaf vs fold into sidecar-response / sidecar-request? | assumed — fold. Add a 405-copy scenario on sidecar-response and an Authelia-shaped POST scenario on sidecar-request. No new 4th part; no Authelia domain. | explore |
| Does build_testing_go need a usage update for upstream_issue_*_test.go? | assumed — yes, one Key files line at implement/devdocsimpact if the file lands. No new Language term. | explore |

## Before merge
- [ ] Propose OpenSpec fold + land `pkg/modsecurity/upstream_issue_13_test.go` [P3]
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
| Reviewed head | 6fe0e7ce302f1f83c17072919caa1bb08265cf81 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Tests-only pin versus `origin/main`; runtime already copies sidecar 4xx and inbound Host.

Do we have a high-confidence way to reproduce? Yes — starter test passed; plugin-invented 405 not reproduced.

Is this the best way to solve the issue? Yes — unit pin without Authelia compose or a 405 knob.

### Evidence
What I checked:
- `go test ./pkg/modsecurity/ -run TestPlugin_UpstreamIssue13_PostFirstFactorNeverEmits405` pass (untracked starter)
- Existing Host/XFF test pass
- Authelia OpenAPI 200/401 only (`knowledge/research/ext_authelia_api_firstfactor/`)

### Rank-up moves
None.
