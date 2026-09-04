Developer review: in progress — 2026-09-04T15:48:47Z

## What this changes
**Operators.** New middleware plugin key `failMode` (`open` or `close`, default `open`). When `close`, a WAF communication failure and the already-unhealthy skip return empty HTTP 502 instead of calling the backend.

**Admin users.** None.

**Developers.** `Config.FailMode` / `Plugin.failMode`; Prepare fills omitted to `open` and rejects other values; `ServeHTTP` branches through `serveFailClosedOrNext` after WAF failure and on unhealthy skip.

**End users.** None unless the operator sets `failMode: close`; then a down sidecar yields HTTP 502 instead of the backend response.

## Motivation
On `main`, a sidecar transport error or sidecar 5xx always calls the next handler. [Upstream issue #20](https://github.com/madebymode/traefik-modsecurity-plugin/issues/20) reported the other production failure: when ModSecurity cannot keep up or is down, 502s take the whole middleware path down. This fork later shipped fail-open as the default; operators still have no plugin setting to choose fail-close. Without this PR they stay fail-open.

## Merge readiness
Apply is on the branch; CI on `eed8ff8` is still running. 3 items remain (code review, docs archive, green CI).

Priority: P2 — operator cannot fail-close when the WAF is down; current deploys keep fail-open
Reviewed head: eed8ff8
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Local tests passed; remote CI in progress |
| CI proof | 3/6 | in progress [33891631018](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33891631018) [33891631010](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33891631010) [33891631011](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33891631011) [33891631042](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33891631042) |
| Local tests proof | N/A | Remote CI is the proof axis; `go test ./...` passed locally |
| Review resolution | 6/6 | OPEN PR; no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-04-fail-open-close pushed | this checkout; HEAD `eed8ff8` |
| OpenSpec | waf-fail-closed | `openspec/changes/waf-fail-closed/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/45 | GitHub |
| CI | in progress [33891631018](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33891631018) | GitHub check runs |
| Local tests | passed | `go test ./...` in this checkout |
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
`failMode` is the operator knob for the tension in [madebymode/traefik-modsecurity-plugin#20](https://github.com/madebymode/traefik-modsecurity-plugin/issues/20): refuse with 502 when the WAF cannot inspect (`close`), or keep fail-open so a down sidecar does not take ingress down (`open`, the default). Apply is on [PR 45](https://github.com/david-garcia-garcia/traefik-modsecurity/pull/45).

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Does fail-close apply to the already-unhealthy skip (today always `next`)? | assumed — yes; otherwise fail-close is bypassed after the tracker trips. | explore |
| What does the client receive on fail-close? | assumed — empty HTTP 502, same as existing plugin-owned 502s. Status-header `error` or `unhealthy` as today. | explore |

## Before merge
- [ ] Green CI on `eed8ff8`
- [ ] Code review and archive

## Findings
- Related: [If the modsec backend fails the whole middleware goes down](https://github.com/madebymode/traefik-modsecurity-plugin/issues/20) — the upstream report of WAF-down 502s taking the path down versus staying up. This PR makes that choice `failMode: close` versus default `open`.

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
| Reviewed head | eed8ff838b01fece4749366242e2ed73498d6345 | Card must match the branch you measured |

### Stored data model
Public Traefik plugin YAML/JSON gains `failMode` (string: `open` or `close`). Omitted stays fail-open. Upgrade compatible. Invalid values fail plugin construction.

### Technical review
Best possible solution versus `main`: one Config string (`open`/`close`), shared `serveFailClosedOrNext` on WAF failure and unhealthy skip, empty 502.

Do we have a high-confidence way to reproduce? Yes, `TestPlugin_WafFailureDefaultFailOpen`, `TestPlugin_FailModeCloseWafFailureReturns502`, `TestPlugin_FailModeCloseUnhealthySkipReturns502`.

Is this the best way to solve the issue? Yes versus `main`. This is the operator setting for [madebymode#20](https://github.com/madebymode/traefik-modsecurity-plugin/issues/20).

### Evidence
What I checked:
- `go test ./...` passed in this checkout (HEAD `eed8ff8`)
- CI in progress on PR 45 after `eed8ff8`
- [madebymode/traefik-modsecurity-plugin#20](https://github.com/madebymode/traefik-modsecurity-plugin/issues/20) cited on this card

### Rank-up moves
None.
