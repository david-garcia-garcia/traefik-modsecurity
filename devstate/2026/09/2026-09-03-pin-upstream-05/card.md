Developer review: in progress — 2026-09-03T04:17:33Z

Upstream: [acouvreur/traefik-modsecurity-plugin#5](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/5)

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None yet versus `main`. Explore recorded assumed decisions; starter tests still untracked.

**End users.** None.

## Motivation
Without this PR, [acouvreur/traefik-modsecurity-plugin#5](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/5) (HTTP/2 abort / Yaegi panic blamed on `isWebsocket`) has no regression tests on this plugin. A later change could reintroduce a panic with no failing test.

## Merge readiness
Explore finished with assumed decisions. Tests not landed. Remaining: propose through pullrequest.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: c90ea0c
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI still in progress; product tests not merged |
| CI proof | 3/6 | Integration tests in progress |
| Local tests proof | N/A | Before implement (`localTests: none`) |
| Review resolution | 6/6 | OPEN PR; no reviewer comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-pin-upstream-05 pushed | `git` |
| OpenSpec | none | no change folder yet |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/32 | pr-host |
| CI | build 33714475615 success; lint success; Integration Tests (nginx/apache) in progress | https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33714475615 |
| Local tests | none | handoff.yaml; explore measured starter tests passed, not recorded as implement |
| PR comments | no comments | inventory empty |
| Security | None. | no codereview.md yet |
| Performance | None. | no codereview.md yet |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local ticket `2026-09-03-pin-upstream-05` / PR #32. Explore measured the starter file passing. Next: propose fold onto `websocket-skip` and `request-context`, then land the tests.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Who owns client address, user, tenant, Host, or trust hop for this change? | assumed — none. Tests do not set or reconstruct identity. Incoming Host stays on `req.Host`; Traefik owns forwarded headers. | explore |
| Keep the starter test that expects panic on `req.Body == nil`? | assumed — yes. Documents residual deny-verb peek. No `recover`. | explore |
| Treat `http.ErrAbortHandler` on HTTP/2 client abort as a pass? | assumed — yes. Go server abort after RST_STREAM, not a plugin nil-deref. | explore |
| Clone acouvreur/traefik-modsecurity-plugin to pin v1.1.0 line 56? | assumed — no. This run pins this plugin’s Go tests. | explore |
| New spec leaf vs fold onto `websocket-skip` and `request-context`? | assumed — fold. FindSpecHost at propose confirms. | explore |
| Write a Go `Header.Values` research folder? | assumed — no. Tests pin stdlib nil-slice behavior. | explore |

## Before merge
- [ ] Land `pkg/modsecurity/upstream_issue_05_test.go` (tests only; no `recover` in ServeHTTP)
- [x] Stub PR #32 opened
- [x] Explore assumed decisions written

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
| Reviewed head | c90ea0cc6611f6fa456fd4ae29b6dd4b107025cf | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: versus `main`, pin #5 with tests only and fold no-panic requirements onto existing websocket-skip and request-context specs.

Do we have a high-confidence way to reproduce? Yes — `go test ./pkg/modsecurity -run TestPlugin_UpstreamIssue05` passed (1.106s). The panic does not happen on this tree.

Is this the best way to solve the issue? Yes — the ticket asked for coverage, not a product change.

### Evidence
What I checked:
- Starter tests passed (`go test ./pkg/modsecurity -run TestPlugin_UpstreamIssue05`)
- `isWebsocket` uses `Header.Values` (`pkg/modsecurity/serve.go`)
- No `recover` in product ServeHTTP
- Existing specs: `core_plugin_middleware_websocket-skip`, `core_plugin_middleware_request-context`

### Rank-up moves
None.
