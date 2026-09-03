Developer review: in progress — 2026-09-03T04:21:18.627Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** OpenSpec change `pin-upstream-authelia-405` folds Authelia-shaped POST 405 scenarios onto sidecar-response and sidecar-request. The unit test is not committed yet.

**End users.** None.

## Motivation
Without this PR, [acouvreur/traefik-modsecurity-plugin#13](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/13) (Authelia login POST 405) has no committed regression pin that this plugin does not invent that status.

## Merge readiness
Propose complete; implement not started. 4 items remain.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: 0c1286c
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Apply-ready OpenSpec; CI not re-measured this card; test not landed |
| CI proof | 3/6 | Prior push still in flight; this head just pushed |
| Local tests proof | N/A | Before implement (`localTests: none`) |
| Review resolution | 6/6 | OPEN PR; no reviewer comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-pin-upstream-13 pushed | `git` / origin |
| OpenSpec | pin-upstream-authelia-405 | `openspec/changes/pin-upstream-authelia-405/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/36 | pr-host |
| CI | not seen | new head 0c1286c just pushed |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | inventory empty |
| Security | None. | no codereview.md |
| Performance | None. | no codereview.md |

## Specs
- [core_plugin_middleware_sidecar-response](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-pin-upstream-13/openspec/changes/pin-upstream-authelia-405/proposal.md) — modified
- [core_plugin_middleware_sidecar-request](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-pin-upstream-13/openspec/changes/pin-upstream-authelia-405/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local caller asked for a tests-only pin of upstream Authelia login POST 405. Propose folded that pin onto existing sidecar specs. Next: land `pkg/modsecurity/upstream_issue_13_test.go`.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Who already owns inbound Host, leftover X-Forwarded-For, and X-Real-Ip on the sidecar request? | assumed — Host owner is Go Request.Host (inbound). XFF / X-Real-Ip owner is Traefik's entrypoint forwarded-headers wrapper (copied as-is). This plugin does not reconstruct those facts from RemoteAddr. | explore |
| Should the issue-13 fixture use Authelia's official JSON body instead of form-urlencoded? | assumed — keep the starter form body. The test pins plugin status/header copy, not Authelia parsing. | explore |
| New spec leaf vs fold into sidecar-response / sidecar-request? | assumed — fold. Add a 405-copy scenario on sidecar-response and an Authelia-shaped POST scenario on sidecar-request. No new 4th part; no Authelia domain. | propose |
| Does build_testing_go need a usage update for upstream_issue_*_test.go? | assumed — yes, one Key files line at implement/devdocsimpact if the file lands. No new Language term. | explore |

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
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs; do not paste diff --stat |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 0c1286cdd476a70ec2240f6fb69fe9da839c18ea | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Fold scenarios onto existing sidecar specs versus `origin/main`; no new Authelia capability.

Do we have a high-confidence way to reproduce? Yes — starter test already passed; implement only lands it.

Is this the best way to solve the issue? Yes — tests-only pin with folded specs.

### Evidence
What I checked:
- `openspec status --change pin-upstream-authelia-405` 4/4 artifacts complete
- FindSpecHost fold sidecar-response and sidecar-request (high)
- Starter test pass in explore

### Rank-up moves
None.
