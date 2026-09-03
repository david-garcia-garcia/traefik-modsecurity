Developer review: in progress — 2026-09-03T04:22:00Z

Upstream: [acouvreur/traefik-modsecurity-plugin#5](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/5)

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Adds `pkg/modsecurity/upstream_issue_05_test.go` so `isWebsocket`, a reporter-shaped empty GET, inbound cancel, and HTTP/2 client abort do not panic or nil-deref. OpenSpec `pin-upstream-issue-05` records those invariants on websocket-skip and request-context. Product ServeHTTP is unchanged.

**End users.** None.

## Motivation
Without this PR, [acouvreur/traefik-modsecurity-plugin#5](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/5) (HTTP/2 abort / Yaegi panic blamed on `isWebsocket`) has no regression tests on this plugin. A later change could reintroduce a panic with no failing test.

## Merge readiness
Tests landed and local package tests passed. CI on this head is queued.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: 560c084
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI queued after the test commit |
| CI proof | 3/6 | Checks queued on 560c084 |
| Local tests proof | N/A | Remote PR; CI is the proof axis. Local `go test ./...` passed |
| Review resolution | 6/6 | OPEN PR; no reviewer comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-pin-upstream-05 pushed | `git` |
| OpenSpec | pin-upstream-issue-05 | `openspec/changes/pin-upstream-issue-05/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/32 | pr-host |
| CI | queued | https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33714774578 |
| Local tests | passed | `go test ./... -count=1` all four packages ok |
| PR comments | no comments | inventory empty |
| Security | None. | no codereview.md yet |
| Performance | None. | no codereview.md yet |

## Specs
- [core_plugin_middleware_websocket-skip](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-pin-upstream-05/openspec/changes/pin-upstream-issue-05/proposal.md) — modified
- [core_plugin_middleware_request-context](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-pin-upstream-05/openspec/changes/pin-upstream-issue-05/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local ticket `2026-09-03-pin-upstream-05` / PR #32. Implement landed the starter tests. Next: four-axis code review.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Who owns client address, user, tenant, Host, or trust hop for this change? | assumed — none. Tests do not set or reconstruct identity. | explore |
| Keep the starter test that expects panic on `req.Body == nil`? | assumed — yes. Documents residual deny-verb peek. No `recover`. | explore |
| Treat `http.ErrAbortHandler` on HTTP/2 client abort as a pass? | assumed — yes. Go server abort after RST_STREAM, not a plugin nil-deref. | explore |
| Clone acouvreur/traefik-modsecurity-plugin to pin v1.1.0 line 56? | assumed — no. This run pins this plugin’s Go tests. | explore |
| Write a Go `Header.Values` research folder? | assumed — no. Tests pin stdlib nil-slice behavior. | explore |

## Before merge
- [x] Land `pkg/modsecurity/upstream_issue_05_test.go` (tests only; no `recover` in ServeHTTP)
- [x] Stub PR #32 opened
- [x] OpenSpec `pin-upstream-issue-05` apply-ready
- [ ] Wait for CI on 560c084

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
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 560c084cfc22e43cb5c17a5b29bef6d7386bb740 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: versus `main`, pin #5 with tests only; ServeHTTP unchanged.

Do we have a high-confidence way to reproduce? Yes — `go test ./pkg/modsecurity -run TestPlugin_UpstreamIssue05` passed.

Is this the best way to solve the issue? Yes — coverage, not a product change.

### Evidence
What I checked:
- `go test ./... -count=1` passed (root, health, modsecurity, reclaim)
- `pkg/modsecurity/serve.go` has no `recover` and no product diff vs `origin/main`
- Tasks 1.1–2.2 marked done

### Rank-up moves
None.
