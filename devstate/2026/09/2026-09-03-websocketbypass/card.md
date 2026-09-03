Developer review: in progress — 2026-09-03T06:49:49.534Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Motivation
On `main`, any GET that adds `Connection: Upgrade` and `Upgrade: websocket` skips ModSecurity (`pkg/modsecurity/serve.go` `isWebsocket`). The same path leaves a client-supplied `modSecurityStatusRequestHeader` (for example `X-Waf-Status: ok`) intact. A non-WebSocket backend still answers ordinary HTTP 200, so GET SQLi, XSS, and scanner probes skip the WAF. Without this PR that skip stays the public contract.

## Merge readiness
Prepare is done. Explore must answer other-WAF WebSocket practice and whether to drop auto-detection before any product change. 2 items remain.

Priority: P1 — Production is unsafe, serving a wrong public contract today
Reviewed head: f627a90
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI still in progress; no product delta yet |
| CI proof | 3/6 | Checks in progress on the empty start commit |
| Local tests proof | N/A | Before implement; remote PR uses CI |
| Review resolution | 6/6 | OPEN PR, no comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-websocketbypass pushed | `git` origin/2026-09-03-websocketbypass |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/41 | pr-host Create |
| CI | build in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33725028239 ; Build in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33725028198 ; lint in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33725028141 ; Integration Tests in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33725028099 | pr-host check_runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | empty get_comments |
| Security | None. | no codereview.md yet |
| Performance | None. | no codereview.md yet |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local spec from `opus_review.md` §1 plus the human's explore questions. Branch `2026-09-03-websocketbypass` from `main` in worktree `wt-modsec-2026-09-03-websocketbypass`. Stub PR #41. Qualify `qualified-with-gaps` until explore decides skip-vs-drop.

## Decision needed
None.

## Before merge
- [ ] [P1] Explore other WAF WebSocket handling and decide skip-vs-drop before product code
- [ ] [P1] Close the client-controlled GET Upgrade skip and status-header spoof on `main`

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
| Specs in this PR | none | Same list as ## Specs; do not paste diff --stat |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | f627a90ebcf90383ac2b6c751b5950f9bbcbf46e | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not chosen yet versus `main`. Explore will compare tightening handshake detection versus dropping auto-skip and using `bypassRules`.

Do we have a high-confidence way to reproduce? Yes, `modsecurity_test.go` "Does not forward Websockets" already asserts the skip; the status-header spoof is not covered because those cases set the header name to empty.

Is this the best way to solve the issue? Not decided. The opus sketch (require `Sec-WebSocket-*`) and the human's drop-detection option are still open.

### Evidence
What I checked:
- `pkg/modsecurity/serve.go:28-31` and `171-185` on `origin/main` (342d3cf)
- Specs `core_plugin_middleware_websocket-skip` and `core_plugin_middleware_status-header`
- Stub PR https://github.com/david-garcia-garcia/traefik-modsecurity/pull/41 (f627a90)
- CI check_runs in progress on that PR

### Rank-up moves
None.
