Developer review: in progress — 2026-09-04T06:10:00Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Motivation
On `main`, a sidecar transport error or sidecar 5xx always calls the next handler. An operator who must not send traffic to the backend when ModSecurity cannot inspect the request has no plugin setting. Without this PR they stay fail-open.

## Merge readiness
Explore recorded assumed knob shape and fail-close scope. Product code is unchanged versus `main`. 6 items remain.

Priority: P2 — operator cannot fail-close when the WAF is down; current deploys keep fail-open
Reviewed head: 742e0c9
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Integration tests still running; no product apply yet |
| CI proof | 3/6 | lint/build succeeded; Integration Tests (nginx-drain) and (apache-drain) in progress: [nginx-drain](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33843181281/job/100929465552), [apache-drain](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33843181281/job/100929465281) |
| Local tests proof | N/A | `localTests: none`; remote CI is the proof axis |
| Review resolution | 6/6 | OPEN PR; no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-04-fail-open-close pushed | git worktree `wt-modsec-2026-09-04-fail-open-close` |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/45 | GitHub |
| CI | in progress [33843181281](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33843181281) | GitHub check runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | GitHub comment list |
| Security | None. | no `devstate/codereview.md` yet |
| Performance | None. | no `devstate/codereview.md` yet |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local spec → dedicated worktree from `origin/main` → branch `2026-09-04-fail-open-close` → stub PR 45. Explore assumed `failClosed` bool (default false), fail-close on unhealthy skip, empty 502.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| What is the public field shape? | assumed — `failClosed` bool, default false (omitempty). Not a string mode. | explore |
| Does fail-close apply to the already-unhealthy skip (today always `next`)? | assumed — yes; otherwise fail-close is bypassed after the tracker trips. | explore |
| What does the client receive on fail-close? | assumed — empty HTTP 502, same as existing plugin-owned 502s. Status-header `error` or `unhealthy` as today. | explore |

## Before merge
- [ ] Add `failClosed` so WAF communication failure can fail-close (default remains fail-open)
- [ ] Update specs that currently forbid HTTP 502 on WAF failure
- [ ] Green CI on the apply, not only bus commits

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
| Specs in this PR | none | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 742e0c9b06e76b068ebedb6243b086bb6cd1d0f5 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: not applied yet versus `main`. Explore chose a bool `failClosed` default false over a string mode.

Do we have a high-confidence way to reproduce? Yes, `TestPlugin_WafFailureNeverFailClosed` and `pkg/modsecurity/serve.go` after sidecar 5xx / transport error.

Is this the best way to solve the issue? Yes versus `main` — one existing-pattern Config bool, fail-close on both the failing request and the unhealthy skip.

### Evidence
What I checked:
- Dedicated worktree `D:/repositories/wt-modsec-2026-09-04-fail-open-close` from `origin/main` `aa6714d` (git worktree list)
- `openspec/specs/core_plugin_middleware_waf-status/spec.md` forbids 502 on WAF failure (read)
- `openspec/specs/core_plugin_middleware_health-tracker/spec.md` unhealthy path always calls `next` (read)
- CI: lint/build success; apache-drain and nginx-drain in progress (GitHub get_check_runs)

### Rank-up moves
None.
