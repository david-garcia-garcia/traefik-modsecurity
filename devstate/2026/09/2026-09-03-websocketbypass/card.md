Developer review: in progress — 2026-09-03T06:56:03.062Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Research packets under `knowledge/research/` for how Cloudflare, AWS WAF, Azure, Cloud Armor, Fastly NGWAF, HAProxy, Coraza, and libmodsecurity treat a WebSocket handshake versus frames after 101. No plugin behavior change yet.

**End users.** None.

## Motivation
On `main`, any GET that adds `Connection: Upgrade` and `Upgrade: websocket` skips ModSecurity (`pkg/modsecurity/serve.go` `isWebsocket`). The same path leaves a client-supplied `modSecurityStatusRequestHeader` intact. A non-WebSocket backend still answers ordinary HTTP 200. Without this PR that skip stays the public contract.

## Merge readiness
Explore is written. Product code is waiting on the assumed skip-vs-drop decision. 2 items remain.

Priority: P1 — Production is unsafe, serving a wrong public contract today
Reviewed head: cdac9f0
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI in progress; no plugin delta yet |
| CI proof | 3/6 | Checks in progress on the research commit |
| Local tests proof | N/A | Before implement; remote PR uses CI |
| Review resolution | 6/6 | OPEN PR, no comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-websocketbypass pushed | `git` origin/2026-09-03-websocketbypass |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/41 | pr-host |
| CI | Integration Tests in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33725567549 ; Build in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33725567642 ; build in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33725567631 ; lint in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33725567497 | pr-host check_runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | empty get_comments |
| Security | None. | no codereview.md yet |
| Performance | None. | no codereview.md yet |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local spec from `opus_review.md` §1. Worktree `wt-modsec-2026-09-03-websocketbypass`. Stub PR #41. Explore decided other WAFs inspect the handshake; this run assumes dropping `isWebsocket` and using `bypassRules` for operator WebSocket paths.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should this plugin drop automatic WebSocket detection and rely on `bypassRules` for operator-chosen WebSocket paths? | assumed — yes. Drop `isWebsocket`. Header-based skip cannot name a WebSocket route. | explore |
| Will sending the handshake to the sidecar break a real WebSocket through Traefik? | assumed — not for this plugin's allow/block split. CRS may 403 a legitimate handshake; then `bypassRules`. | explore |
| Who owns “this request is a WebSocket”? | assumed — none in this plugin. The operator owns the skip via `bypassRules` or router wiring. | explore |

## Before merge
- [ ] [P1] Confirm drop of `isWebsocket` (or choose a different skip policy)
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
| Specs in this PR | none | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | cdac9f023d6ec4be9ae9553d5de1849243b966b7 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Drop automatic skip (industry inspects the handshake HTTP request). Tightening `Sec-WebSocket-*` still leaves a client-controlled skip. Operators who need a skip already have `bypassRules`. Independently strip the status header at the top of `ServeHTTP`.

Do we have a high-confidence way to reproduce? Yes. `TestModsecurity_ServeHTTP/Does_not_forward_Websockets` still passes (skip is intended on `main`). A throwaway test (deleted, not committed) showed GET + Upgrade + `X-Waf-Status: ok` reached `next` with `ok` and zero sidecar hits.

Is this the best way to solve the issue? Yes versus `main`, if the assumed drop is accepted: other WAFs inspect the handshake; header detection cannot name a route.

### Evidence
What I checked:
- `pkg/modsecurity/serve.go:28-31` and `171-185` on origin/main (342d3cf)
- `go test -count=1 -v -run TestModsecurity_ServeHTTP` (PASS, including Does_not_forward_Websockets)
- Official Cloudflare / AWS / Azure / Cloud Armor / Fastly / HAProxy / Coraza / ModSecurity notes in `knowledge/research/`
- Stub PR https://github.com/david-garcia-garcia/traefik-modsecurity/pull/41 (cdac9f0)

### Rank-up moves
None.
