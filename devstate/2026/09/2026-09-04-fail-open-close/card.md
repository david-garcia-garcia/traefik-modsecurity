Developer review: in progress — 2026-09-04T06:18:17Z

## What this changes
**Operators.** New middleware plugin key `failClosed` (default `false`). When `true`, a WAF communication failure and the already-unhealthy skip return empty HTTP 502 instead of calling the backend.

**Admin users.** None.

**Developers.** `Config.FailClosed` / `Plugin.failClosed`; `ServeHTTP` branches through `serveNextOrFailClosed` after WAF failure and on unhealthy skip.

**End users.** None unless the operator sets `failClosed: true`; then a down sidecar yields HTTP 502 instead of the backend response.

## Motivation
On `main`, a sidecar transport error or sidecar 5xx always calls the next handler. An operator who must not send traffic to the backend when ModSecurity cannot inspect the request has no plugin setting. Without this PR they stay fail-open.

## Merge readiness
Apply is on the branch; CI on the apply commit is still running. 3 items remain (code review, docs archive, green CI).

Priority: P2 — operator cannot fail-close when the WAF is down; current deploys keep fail-open
Reviewed head: eaf636b
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Local tests passed; remote CI in progress |
| CI proof | 3/6 | in progress [33843803882](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33843803882) [33843803942](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33843803942) |
| Local tests proof | N/A | Remote CI is the proof axis; `go test ./...` passed locally |
| Review resolution | 6/6 | OPEN PR; no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-04-fail-open-close pushed | worktree `wt-modsec-2026-09-04-fail-open-close` |
| OpenSpec | waf-fail-closed | `openspec/changes/waf-fail-closed/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/45 | GitHub |
| CI | in progress [33843803882](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33843803882) | GitHub check runs |
| Local tests | passed | `go test ./...` in the worktree |
| PR comments | no comments | GitHub |
| Security | None. | no `devstate/codereview.md` yet |
| Performance | None. | no `devstate/codereview.md` yet |

## Specs
- [core_plugin_middleware_fail-closed](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-04-fail-open-close/openspec/changes/waf-fail-closed/proposal.md) — added
- [core_plugin_middleware_waf-status](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-04-fail-open-close/openspec/changes/waf-fail-closed/proposal.md) — modified
- [core_plugin_middleware_health-tracker](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-04-fail-open-close/openspec/changes/waf-fail-closed/proposal.md) — modified
- [core_plugin_middleware_log-level](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-04-fail-open-close/openspec/changes/waf-fail-closed/proposal.md) — modified
- [core_plugin_middleware_sidecar-response](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-04-fail-open-close/openspec/changes/waf-fail-closed/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Dedicated worktree from `origin/main` → `failClosed` apply on PR 45. Default remains fail-open.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| What is the public field shape? | assumed — `failClosed` bool, default false (omitempty). Not a string mode. | explore |
| Does fail-close apply to the already-unhealthy skip (today always `next`)? | assumed — yes; otherwise fail-close is bypassed after the tracker trips. | explore |
| What does the client receive on fail-close? | assumed — empty HTTP 502, same as existing plugin-owned 502s. Status-header `error` or `unhealthy` as today. | explore |

## Before merge
- [ ] Green CI on `eaf636b`
- [ ] Code review and archive

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
| Specs in this PR | 1 added / 4 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | eaf636bb4e0b10331290202cef3692c89b1f478d | Card must match the branch you measured |

### Stored data model
Public Traefik plugin YAML/JSON gains `failClosed` (bool). Omitted stays fail-open. Upgrade compatible.

### Technical review
Best possible solution versus `main`: one Config bool, shared `serveNextOrFailClosed` on WAF failure and unhealthy skip, empty 502.

Do we have a high-confidence way to reproduce? Yes, `TestPlugin_WafFailureDefaultFailOpen`, `TestPlugin_FailClosedWafFailureReturns502`, `TestPlugin_FailClosedUnhealthySkipReturns502`.

Is this the best way to solve the issue? Yes versus `main`.

### Evidence
What I checked:
- `go test ./...` passed in `D:/repositories/wt-modsec-2026-09-04-fail-open-close` (HEAD `eaf636b`)
- Worktree parent is `origin/main` `aa6714d`
- CI in progress on PR 45

### Rank-up moves
None.
