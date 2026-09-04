Developer review: in progress — 2026-09-04T06:14:28Z

## What this changes
**Operators.** None yet versus `main` (proposal only). Planned knob: `failClosed` (default false).

**Admin users.** None.

**Developers.** OpenSpec change `waf-fail-closed` adds `core_plugin_middleware_fail-closed` and modifies waf-status, health-tracker, log-level, and sidecar-response.

**End users.** None.

## Motivation
On `main`, a sidecar transport error or sidecar 5xx always calls the next handler. An operator who must not send traffic to the backend when ModSecurity cannot inspect the request has no plugin setting. Without this PR they stay fail-open.

## Merge readiness
Proposal is apply-ready; product code is still unchanged versus `main`. 5 items remain.

Priority: P2 — operator cannot fail-close when the WAF is down; current deploys keep fail-open
Reviewed head: 943f2d6
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | New CI run in progress on the proposal commit |
| CI proof | 3/6 | in progress [33843540752](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33843540752) |
| Local tests proof | N/A | `localTests: none`; remote CI is the proof axis |
| Review resolution | 6/6 | OPEN PR; no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-04-fail-open-close pushed | worktree `wt-modsec-2026-09-04-fail-open-close` |
| OpenSpec | waf-fail-closed | `openspec/changes/waf-fail-closed/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/45 | GitHub |
| CI | in progress [33843540752](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33843540752) | GitHub check runs |
| Local tests | none | handoff.yaml localTests |
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
Dedicated worktree from `origin/main` → branch `2026-09-04-fail-open-close` → PR 45. Change `waf-fail-closed` is apply-ready.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| What is the public field shape? | assumed — `failClosed` bool, default false (omitempty). Not a string mode. | explore |
| Does fail-close apply to the already-unhealthy skip (today always `next`)? | assumed — yes; otherwise fail-close is bypassed after the tracker trips. | explore |
| What does the client receive on fail-close? | assumed — empty HTTP 502, same as existing plugin-owned 502s. Status-header `error` or `unhealthy` as today. | explore |

## Before merge
- [ ] Apply `failClosed` in Config, Plugin, and ServeHTTP
- [ ] Green CI on the apply

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
| Reviewed head | 943f2d6944a06188f0c58e41676315b49eb38d66 | Card must match the branch you measured |

### Stored data model
Public Traefik plugin YAML/JSON will gain `failClosed` (bool). Omitted stays fail-open. Upgrade compatible.

### Technical review
Best possible solution versus `main`: one bool on existing Config, fail-close on WAF failure and unhealthy skip, empty 502.

Do we have a high-confidence way to reproduce? Yes, current fail-open tests and `serve.go`.

Is this the best way to solve the issue? Yes versus `main` — matches other typed Config knobs.

### Evidence
What I checked:
- Worktree `D:/repositories/wt-modsec-2026-09-04-fail-open-close` at `943f2d6` from `origin/main` `aa6714d` (git)
- `openspec validate waf-fail-closed` passed
- PR https://github.com/david-garcia-garcia/traefik-modsecurity/pull/45

### Rank-up moves
None.
