Developer review: in progress — 2026-09-03T04:17:43Z

[acouvreur/traefik-modsecurity-plugin#9](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/9)

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Research folder `knowledge/research/ext_http_maxbytesreader/` records that `http.MaxBytesReader` with limit 0 returns `*http.MaxBytesError` on any non-empty body. The #9 login-POST tests are not on this branch yet.

**End users.** None.

## Motivation
`origin/main` remaps omitted/`0` `maxBodySizeBytes` to 8 MiB and skips `MaxBytesReader` when the handler field is 0, but it has no test that a login-sized POST stays 200. Without this PR a later change can reintroduce the upstream 1.2.0 every-POST 413 and CI will not catch it.

## Merge readiness
Prepare done; tests and spec not landed. 3 items remain.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: b3b2a7f
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI still running; tests not landed |
| CI proof | 3/6 | Checks in progress |
| Local tests proof | N/A | Before implement |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-pin-upstream-09 pushed | git |
| OpenSpec | none | openspec/ |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/37 | pr-host Create |
| CI | lint/build/integration in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33714507133 | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | inventory empty |
| Security | None. | no codereview.md |
| Performance | None. | no codereview.md |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local ticket 2026-09-03-pin-upstream-09 is on branch `2026-09-03-pin-upstream-09` as PR #37. Prepare grounded the #9 pin; explore through pullrequest still run.

## Decision needed
None.

## Before merge
- [ ] Land `pkg/modsecurity/upstream_issue_09_test.go` (tests only)
- [ ] OpenSpec change for the #9 pin
- [ ] CI succeeded on PR #37

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
| Specs in this PR | none | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | b3b2a7f0bee707a4193967a5cfa5267cc5df2745 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Pin the existing Prepare remap and MaxBytesReader skip with tests; do not change the cap.

Do we have a high-confidence way to reproduce? Yes, the starter file and stdlib MaxBytesReader(0) case.

Is this the best way to solve the issue? Yes versus DestBranch: tests-only pin, no product change.

### Evidence
What I checked:
- Prepare remaps MaxBodySizeBytes 0 to 8 MiB (`pkg/modsecurity/config.go`, 2f39486)
- readInboundBody skips MaxBytesReader when limit is 0 (`pkg/modsecurity/body.go`, 2f39486)
- Upstream issue #9 is the 1.2.0 login POST 413 (github.com/acouvreur/traefik-modsecurity-plugin/issues/9)
- Stub PR #37 created; CI in progress (run 33714507133)

### Rank-up moves
None.
