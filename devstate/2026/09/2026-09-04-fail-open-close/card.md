Developer review: in progress — 2026-09-04T16:10:46Z

## What this changes
**Operators.** New middleware plugin key `failMode` (`open` or `close`, default `open`). When `close`, a WAF communication failure and the already-unhealthy skip return empty HTTP 502 instead of calling the backend.

**Admin users.** None.

**Developers.** `Config.FailMode` / `Plugin.failMode`; Prepare fills omitted to `open` and rejects other values; `ServeHTTP` branches through `serveFailClosedOrNext` after WAF failure and on unhealthy skip.

**End users.** None unless the operator sets `failMode: close`; then a down sidecar yields HTTP 502 instead of the backend response.

## Motivation
On `main`, a sidecar transport error or sidecar 5xx always calls the next handler. [Upstream issue #20](https://github.com/madebymode/traefik-modsecurity-plugin/issues/20) reported the other production failure: when ModSecurity cannot keep up or is down, 502s take the whole middleware path down. This fork later shipped fail-open as the default; operators still have no plugin setting to choose fail-close. Without this PR they stay fail-open.

## Merge readiness
Code review of `origin/main...HEAD` is done (no hard findings). 2 items remain (docs archive, keep CI green after remaining commits).

Priority: P2 — operator cannot fail-close when the WAF is down; current deploys keep fail-open
Reviewed head: 1b337be
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Local tests passed; remote CI succeeded; no open review comments |
| CI proof | 6/6 | succeeded [33891746661](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33891746661) [33891746601](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33891746601) [33891746612](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33891746612) [33891746609](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33891746609) |
| Local tests proof | N/A | Remote CI is the proof axis |
| Review resolution | 6/6 | OPEN PR; no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-04-fail-open-close pushed | this checkout; HEAD `1b337be` |
| OpenSpec | waf-fail-closed | `openspec/changes/waf-fail-closed/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/45 | GitHub |
| CI | succeeded [33891746661](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33891746661) | GitHub check runs |
| Local tests | passed | `handoff.yaml` |
| PR comments | no comments | GitHub |
| Security | None. | `devstate/codereview.md` |
| Performance | None. | `devstate/codereview.md` |

## Specs
- [core_plugin_middleware_fail-closed](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-04-fail-open-close/openspec/changes/waf-fail-closed/proposal.md) — added
- [core_plugin_middleware_waf-status](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-04-fail-open-close/openspec/changes/waf-fail-closed/proposal.md) — modified
- [core_plugin_middleware_health-tracker](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-04-fail-open-close/openspec/changes/waf-fail-closed/proposal.md) — modified
- [core_plugin_middleware_log-level](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-04-fail-open-close/openspec/changes/waf-fail-closed/proposal.md) — modified
- [core_plugin_middleware_sidecar-response](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-04-fail-open-close/openspec/changes/waf-fail-closed/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
`failMode` is the operator knob for the tension in [madebymode/traefik-modsecurity-plugin#20](https://github.com/madebymode/traefik-modsecurity-plugin/issues/20): refuse with 502 when the WAF cannot inspect (`close`), or keep fail-open so a down sidecar does not take ingress down (`open`, the default). Apply is on [PR 45](https://github.com/david-garcia-garcia/traefik-modsecurity/pull/45). Four-axis review of `origin/main...HEAD` found no hard issues.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Does fail-close apply to the already-unhealthy skip (today always `next`)? | assumed — yes; otherwise fail-close is bypassed after the tracker trips. | explore |
| What does the client receive on fail-close? | assumed — empty HTTP 502, same as existing plugin-owned 502s. Status-header `error` or `unhealthy` as today. | explore |

## Before merge
- [x] Green CI on `1b337be`
- [x] Four-axis code review (`devstate/codereview.md`)
- [ ] OpenSpec archive

## Findings
- Related: [If the modsec backend fails the whole middleware goes down](https://github.com/madebymode/traefik-modsecurity-plugin/issues/20) — the upstream report of WAF-down 502s taking the path down versus staying up. This PR makes that choice `failMode: close` versus default `open`.
- [[P3] extra inbound body-read status-header test](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-04-fail-open-close/pkg/modsecurity/body_test.go) — extra — locks header unset on non-413 inbound body-read 502; not a `waf-fail-closed` SHALL. Path: `pkg/modsecurity/body_test.go`. Reply none.
- [[P3] extra usage bullet for WAF-only error](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-04-fail-open-close/knowledge/devdocs/core_plugin_middleware.md) — extra — same correction in usage docs. Path: `knowledge/devdocs/core_plugin_middleware.md`. Reply none.

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
| Reviewed head | 1b337bea99c9e02f3f84039a2e148384954995fe | Card must match the branch you measured |

### Stored data model
Public Traefik plugin YAML/JSON gains `failMode` (string: `open` or `close`). Omitted stays fail-open. Upgrade compatible. Invalid values fail plugin construction.

### Technical review
Best possible solution versus `main`: one Config string (`open`/`close`), shared `serveFailClosedOrNext` on WAF failure and unhealthy skip, empty 502.

Do we have a high-confidence way to reproduce? Yes, `TestPlugin_WafFailureDefaultFailOpen`, `TestPlugin_FailModeCloseWafFailureReturns502`, `TestPlugin_FailModeCloseUnhealthySkipReturns502`.

Is this the best way to solve the issue? Yes versus `main`. This is the operator setting for [madebymode#20](https://github.com/madebymode/traefik-modsecurity-plugin/issues/20).

### Evidence
What I checked:
- Four-axis review of `origin/main...HEAD` (Standards none, Spec 2 extra, Security none, Performance none)
- CI succeeded on PR 45 head `1b337be` (runs 33891746661, 33891746601, 33891746612, 33891746609)
- [madebymode/traefik-modsecurity-plugin#20](https://github.com/madebymode/traefik-modsecurity-plugin/issues/20) cited on this card

### Rank-up moves
None.
