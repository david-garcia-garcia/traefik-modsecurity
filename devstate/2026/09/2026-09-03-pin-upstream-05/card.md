Developer review: in progress — 2026-09-03T04:20:15Z

Upstream: [acouvreur/traefik-modsecurity-plugin#5](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/5)

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** OpenSpec change `pin-upstream-issue-05` adds no-panic requirements on `core_plugin_middleware_websocket-skip` and `core_plugin_middleware_request-context`. Starter tests are still untracked.

**End users.** None.

## Motivation
Without this PR, [acouvreur/traefik-modsecurity-plugin#5](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/5) (HTTP/2 abort / Yaegi panic blamed on `isWebsocket`) has no regression tests on this plugin. A later change could reintroduce a panic with no failing test.

## Merge readiness
Propose is apply-ready. Tests not landed. Remaining: implement through pullrequest.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: adaf30d
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI in progress; tests not landed |
| CI proof | 3/6 | Integration tests in progress on latest push |
| Local tests proof | N/A | Before implement (`localTests: none`) |
| Review resolution | 6/6 | OPEN PR; no reviewer comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-pin-upstream-05 pushed | `git` |
| OpenSpec | pin-upstream-issue-05 | `openspec/changes/pin-upstream-issue-05/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/32 | pr-host |
| CI | lint/build success; Integration Tests (nginx/apache) in progress | https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33714554047 |
| Local tests | none | handoff.yaml |
| PR comments | no comments | inventory empty |
| Security | None. | no codereview.md yet |
| Performance | None. | no codereview.md yet |

## Specs
- [core_plugin_middleware_websocket-skip](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-pin-upstream-05/openspec/changes/pin-upstream-issue-05/proposal.md) — modified
- [core_plugin_middleware_request-context](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-pin-upstream-05/openspec/changes/pin-upstream-issue-05/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local ticket `2026-09-03-pin-upstream-05` / PR #32. Propose folded no-panic invariants onto existing specs. Next: land `upstream_issue_05_test.go`.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Who owns client address, user, tenant, Host, or trust hop for this change? | assumed — none. Tests do not set or reconstruct identity. | explore |
| Keep the starter test that expects panic on `req.Body == nil`? | assumed — yes. Documents residual deny-verb peek. No `recover`. | explore |
| Treat `http.ErrAbortHandler` on HTTP/2 client abort as a pass? | assumed — yes. Go server abort after RST_STREAM, not a plugin nil-deref. | explore |
| Clone acouvreur/traefik-modsecurity-plugin to pin v1.1.0 line 56? | assumed — no. This run pins this plugin’s Go tests. | explore |
| Write a Go `Header.Values` research folder? | assumed — no. Tests pin stdlib nil-slice behavior. | explore |

## Before merge
- [ ] Land `pkg/modsecurity/upstream_issue_05_test.go` (tests only; no `recover` in ServeHTTP)
- [x] Stub PR #32 opened
- [x] OpenSpec `pin-upstream-issue-05` apply-ready

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
| Reviewed head | adaf30da7e843eb444c69b423333f090dca3e122 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: versus `main`, pin #5 with tests and fold no-panic requirements onto websocket-skip and request-context.

Do we have a high-confidence way to reproduce? Yes — starter tests already pass on this tree.

Is this the best way to solve the issue? Yes — coverage only; no product change.

### Evidence
What I checked:
- `openspec validate pin-upstream-issue-05 --type change --strict` passed
- FindSpecHost fold verdicts on `devstate/specs.md`

### Rank-up moves
None.
