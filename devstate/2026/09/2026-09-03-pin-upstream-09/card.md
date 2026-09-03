Developer review: in progress — 2026-09-03T04:20:26Z

[acouvreur/traefik-modsecurity-plugin#9](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/9)

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Research folder `knowledge/research/ext_http_maxbytesreader/` records that `http.MaxBytesReader` with limit 0 returns `*http.MaxBytesError` on any non-empty body. The #9 login-POST tests are not committed yet (untracked starter already passes).

**End users.** None.

## Motivation
`origin/main` remaps omitted/`0` `maxBodySizeBytes` to 8 MiB and skips `MaxBytesReader` when the handler field is 0, but it has no test that a login-sized POST stays 200. Without this PR a later change can reintroduce the upstream 1.2.0 every-POST 413 and CI will not catch it.

## Merge readiness
Explore done with assumed Decisions. Tests and spec not landed. 3 items remain.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: 178c040
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI still running; tests not landed |
| CI proof | 3/6 | lint/build succeeded; integration in progress |
| Local tests proof | N/A | Before implement |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-pin-upstream-09 pushed | git |
| OpenSpec | none | openspec/ |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/37 | pr-host |
| CI | lint/build success; integration in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33714585359 | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | inventory empty |
| Security | None. | no codereview.md |
| Performance | None. | no codereview.md |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local ticket 2026-09-03-pin-upstream-09 is PR #37. Explore measured the starter tests pass; propose will add `pin-upstream-issue-09`.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Which spec leaf owns the #9 pin (Prepare 8 MiB + leftover-0 skip + login POST 200)? | assumed — new `core_plugin_middleware_maxbodysize`; do not fold into `prepare-validation` or `body-pool`. | explore |
| Should `NewLogger` be called on unprepared cfg (starter order)? | assumed — keep starter; `New` calls `Prepare`; measured pass 2026-09-03. | explore |
| Who already owns client address / user / tenant / Host / trust hop for this pin? | assumed — none; this work does not reconstruct identity; tests use httptest Host only. | explore |
| Does `core_plugin_middleware.md` need a MaxBytesReader skip sentence this run? | assumed — yes, one usage sentence when implement or devdocsimpact runs; no Language write. | explore |

## Before merge
- [ ] Land `pkg/modsecurity/upstream_issue_09_test.go` (tests only)
- [ ] OpenSpec change `pin-upstream-issue-09`
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
| Reviewed head | 178c0407e37c0e61d02c2904e27d62294ff649a3 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Pin the existing Prepare remap and MaxBytesReader skip with tests; do not change the cap.

Do we have a high-confidence way to reproduce? Yes, `go test ./pkg/modsecurity/ -run TestUpstreamIssue09` passed on this tree.

Is this the best way to solve the issue? Yes versus DestBranch: tests-only pin, no product change.

### Evidence
What I checked:
- Starter tests pass (`go test ./pkg/modsecurity/ -run TestUpstreamIssue09`, 2026-09-03)
- Prepare remaps 0 to 8 MiB (`pkg/modsecurity/config.go`)
- readInboundBody skips MaxBytesReader when limit is 0 (`pkg/modsecurity/body.go`)
- PR #37 CI: lint/build success; integration in progress (run 33714585359)

### Rank-up moves
None.
