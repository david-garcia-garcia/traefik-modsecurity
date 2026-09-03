Developer review: in progress — 2026-09-03T05:45:13Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Motivation
`origin/main` has no operator allowlist to skip the ModSecurity sidecar for selected method+path patterns. Without this PR, high-frequency or admin routes stay on the sidecar hop, or the operator must omit the middleware on a separate Traefik router.

## Merge readiness
Stub PR #40 is open; product delta vs `origin/main` is empty. 1 item remains (land bypassRules).

Priority: P2 — real operator pain, with a workaround (separate router without the plugin)
Reviewed head: 27e7b24
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI still in progress; no product apply yet |
| CI proof | 3/6 | Checks in progress on the empty start commit |
| Local tests proof | N/A | prHost remote |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-add-bypass-routes pushed | git |
| OpenSpec | none | openspec/changes |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/40 | pr-host Create |
| CI | build 33720181861 in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33720181861 | pr-host CI (lint job) |
| Local tests | none | handoff.yaml |
| PR comments | no comments | inventory empty |
| Security | None. | no apply yet |
| Performance | None. | no apply yet |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local ticket 2026-09-03-add-bypass-routes is OPEN PR #40. Requirement is qualified-with-gaps. Delivery card is this PR summary.

## Decision needed
None.

## Before merge
- [ ] Land `bypassRules` with one VERB->regex lookup and status-header token `bypassrule`

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
| Reviewed head | 27e7b2412c4199d9c007c5230def68cdd3cacd71 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not applied yet. DestBranch still has no bypass allowlist.

Do we have a high-confidence way to reproduce? No product path yet; gap is `not found` on `Config.BypassRules`.

Is this the best way to solve the issue? Not applied. Ticket forbids the fork's per-request slice scan.

### Evidence
What I checked:
- `pkg/modsecurity/config.go` has no BypassRules
- `pkg/modsecurity/serve.go` status tokens are unhealthy/error/blocked/ok
- Stub PR #40 created from empty start commit 27e7b24
- Check runs on PR 40 in_progress (lint, build, Build, integration matrix, test-runner)

### Rank-up moves
None.
