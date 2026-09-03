Developer review: ready for review — 2026-09-03T04:36:14Z

Upstream: [acouvreur/traefik-modsecurity-plugin#5](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/5)

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Adds `pkg/modsecurity/upstream_issue_05_test.go` so handshake detection, a reporter-shaped empty GET, inbound cancel, and HTTP/2 client abort do not panic or nil-deref. Baseline specs `core_plugin_middleware_websocket-skip` and `core_plugin_middleware_request-context` now include those invariants. Product ServeHTTP is unchanged (no `recover`).

**End users.** None.

## Motivation
Without this PR, [acouvreur/traefik-modsecurity-plugin#5](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/5) (HTTP/2 abort / Yaegi panic blamed on `isWebsocket`) has no regression tests on this plugin. A later change could reintroduce a panic with no failing test.

## Merge readiness
One OPEN PR, CI succeeded, checklist empty. Ready for review.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: 3f49f82
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | CI succeeded; no open review comments |
| CI proof | 6/6 | All required checks succeeded |
| Local tests proof | N/A | Remote PR; CI is the proof axis |
| Review resolution | 6/6 | OPEN PR; no reviewer comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-pin-upstream-05 pushed | `git` tracking `origin/2026-09-03-pin-upstream-05` |
| OpenSpec | pin-upstream-issue-05 archived | `openspec/changes/archive/2026-09-03-pin-upstream-issue-05/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/32 | pr-host |
| CI | build 33715015433 success; lint 33715015542 success; Integration Tests apache/nginx success | https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33715015433 |
| Local tests | passed | `go test ./... -count=1` |
| PR comments | no comments | inventory empty |
| Security | None. | `devstate/codereview.md` |
| Performance | None. | `devstate/codereview.md` |

## Specs
- [core_plugin_middleware_websocket-skip](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-pin-upstream-05/openspec/changes/archive/2026-09-03-pin-upstream-issue-05/proposal.md) — modified
- [core_plugin_middleware_request-context](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-pin-upstream-05/openspec/changes/archive/2026-09-03-pin-upstream-issue-05/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local ticket `2026-09-03-pin-upstream-05` is PR #32 against `main`. Tests pin [acouvreur/traefik-modsecurity-plugin#5](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/5). CI on head `3f49f82` succeeded.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Who owns client address, user, tenant, Host, or trust hop for this change? | assumed — none. Tests do not set or reconstruct identity. | explore |
| Keep the starter test that expects panic on `req.Body == nil`? | assumed — yes. Documents residual deny-verb peek. No `recover`. | explore |
| Treat `http.ErrAbortHandler` on HTTP/2 client abort as a pass? | assumed — yes. Go server abort after RST_STREAM, not a plugin nil-deref. | explore |
| Clone acouvreur/traefik-modsecurity-plugin to pin v1.1.0 line 56? | assumed — no. This run pins this plugin’s Go tests. | explore |
| Write a Go `Header.Values` research folder? | assumed — no. Tests pin stdlib nil-slice behavior. | explore |

## Before merge
None.

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
| Reviewed head | 3f49f8255dd31bb42aad3fec0aac0da220e8b497 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: versus `main`, pin #5 with tests and fold no-panic SHALLs onto existing specs. ServeHTTP is unchanged.

Do we have a high-confidence way to reproduce? Yes — `go test ./pkg/modsecurity -run TestPlugin_UpstreamIssue05` passed; CI Go tests and integration succeeded.

Is this the best way to solve the issue? Yes — the ticket asked for coverage, not a product change.

### Evidence
What I checked:
- CI: lint, build, go test, Integration Tests (apache), Integration Tests (nginx), Test Runner Script Validation — all success
- One OPEN PR #32
- `localTests: passed`

### Rank-up moves
None.
