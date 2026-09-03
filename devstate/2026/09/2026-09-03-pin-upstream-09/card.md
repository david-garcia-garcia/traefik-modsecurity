Developer review: in progress — 2026-09-03T04:25:13Z

[acouvreur/traefik-modsecurity-plugin#9](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/9)

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** `pkg/modsecurity/upstream_issue_09_test.go` pins that omitted/`0` `maxBodySizeBytes` prepares to 8 MiB and a login-sized POST is 200; a leftover handler field 0 does not 413. Spec `core_plugin_middleware_maxbodysize` is in the change folder.

**End users.** None.

## Motivation
`origin/main` remaps omitted/`0` `maxBodySizeBytes` to 8 MiB and skips `MaxBytesReader` when the handler field is 0, but it has no test that a login-sized POST stays 200. Without this PR a later change can reintroduce the upstream 1.2.0 every-POST 413 and CI will not catch it.

## Merge readiness
Tests landed; local `go test ./...` passed. CI on the implement push is still queued. 1 item remains.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: d32880e
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Remote CI not finished |
| CI proof | 3/6 | Checks queued after implement push |
| Local tests proof | N/A | prHost remote; CI covers remote |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-pin-upstream-09 pushed | git |
| OpenSpec | pin-upstream-issue-09 | openspec/changes/pin-upstream-issue-09/ |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/37 | pr-host |
| CI | queued https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33714973015 | pr-host CI |
| Local tests | passed | `go test ./...` 2026-09-03 |
| PR comments | no comments | inventory empty |
| Security | None. | no codereview.md yet |
| Performance | None. | no codereview.md yet |

## Specs
- [core_plugin_middleware_maxbodysize](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-pin-upstream-09/openspec/changes/pin-upstream-issue-09/proposal.md) — added

## Follow-up issues
None.

## How this fits together
Local ticket 2026-09-03-pin-upstream-09 is PR #37. Implement landed the #9 tests; code review and archive still run.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Which spec leaf owns the #9 pin (Prepare 8 MiB + leftover-0 skip + login POST 200)? | assumed — new `core_plugin_middleware_maxbodysize`; do not fold into `prepare-validation` or `body-pool`. | explore |
| Should `NewLogger` be called on unprepared cfg (starter order)? | assumed — keep starter; `New` calls `Prepare`; measured pass 2026-09-03. | explore |
| Who already owns client address / user / tenant / Host / trust hop for this pin? | assumed — none; this work does not reconstruct identity; tests use httptest Host only. | explore |

## Before merge
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
| Specs in this PR | 1 added / 0 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | d32880e7fd7ebcdcc28fb2e72579240de545ef43 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Pin the existing Prepare remap and MaxBytesReader skip with tests; do not change the cap.

Do we have a high-confidence way to reproduce? Yes, `go test ./...` passed including TestUpstreamIssue09.

Is this the best way to solve the issue? Yes versus DestBranch: tests-only pin plus a dedicated spec leaf.

### Evidence
What I checked:
- `go test ./...` passed (root, health, modsecurity, reclaim)
- Starter file landed as-is (`pkg/modsecurity/upstream_issue_09_test.go`)
- Usage sentence added on `core_plugin_middleware.md`

### Rank-up moves
None.
