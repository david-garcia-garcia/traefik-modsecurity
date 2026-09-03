Developer review: in progress — 2026-09-03T03:51:24Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Motivation
On main, every CRS inspect still `ProxyPass` / `proxy_pass` to an unlabeled dummy whoami. That hop is not the real app, so a large body or a `Range` header can become a sidecar 4xx that this plugin copies as a security block, and operators confuse dummy with Traefik’s backend. Without this PR those false blocks and the extra hop stay.

## Merge readiness
Prepare is grounded (`qualified-with-gaps`); the overlay is not implemented. 3 items remain.

Priority: P2 — real operator pain from dummy/whoami (false 4xx blocks, extra hop), with a workaround of keeping dummy
Reviewed head: 066ca7c
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI still running; product overlay not started |
| CI proof | 3/6 | Integration Tests in progress; lint/build succeeded |
| Local tests proof | N/A | Before implement (`localTests: none`) |
| Review resolution | 6/6 | OPEN PR 31, no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-remove-2nd-hop pushed | `git`; origin/2026-09-03-remove-2nd-hop |
| OpenSpec | none | `openspec/changes/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/31 | GitHub list |
| CI | Integration Tests (apache) in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33712807613/job/100515693751 ; Integration Tests (nginx) in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33712807613/job/100515693774 ; Test Runner Script Validation success https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33712807613/job/100515693686 ; lint success https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33712807609/job/100515693669 ; build success https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33712807632/job/100515693600 ; Build success https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33712807601/job/100515693506 | pull_request_read get_check_runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | pull_request_read get_comments / get_review_comments |
| Security | None. | no apply; no `codereview.md` |
| Performance | not seen — before/after allow-path throughput not measured | caller asked for numbers on this card; prepare did not bench |

## Specs
None.

## Follow-up issues
- [ ] [note] [large] README `BenchmarkProtectedEndpoint` → no `Benchmark*` in this tree — README documents an integration bench that is not found. Not this ticket.

## How this fits together
Local inspect-only sidecar spec is grounded on branch 2026-09-03-remove-2nd-hop as PR 31 against main. Next phase is explore (including the nginx `return` vs CRS phase-2 question and a before-change throughput measurement).

## Decision needed
None.

## Before merge
- [ ] Overlay CRS so the sidecar answers HTTP 200 after request phases; delete unlabeled `dummy`
- [ ] Measure allow-path throughput before the overlay and after; put before, after, and delta on this card
- [ ] Prove live CRS gates: GET+POST allow, URI block, POST-body block, Range not sidecar 416, client-IP audit, no dummy service

## Findings
None.

## Agent review details

### Security
None.

### Performance
Before/after allow-path throughput is not measured. Implement must bench on the live stack and put the numbers here. Do not add a `Benchmark*` suite unless that is the only way to get them.

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as Specs; no product spec yet |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 066ca7cfce5d7acc7c889f3036256e923a94fdba | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: not implemented. DestBranch still proxies CRS to dummy whoami.

Do we have a high-confidence way to reproduce? Yes — compose `dummy` + `BACKEND=http://dummy` and `crs-apache/httpd-vhosts.conf` `ProxyPass`.

Is this the best way to solve the issue? Not decided in prepare. Explore must confirm nginx `return 200` still runs CRS request-body inspection before we lock that overlay.

### Evidence
What I checked:
- Local spec dumped from `modsecissues/inspect-only-sidecar.md` plus caller extras (worktree, before/after throughput on this card)
- `qualify: qualified-with-gaps` (`requirement.md`; CRS overlay phase-2 and throughput still unknown)
- Worktree `D:/repositories/traefik-modsecurity-plugin-2026-09-03-remove-2nd-hop` from `origin/main` at `2f39486`
- Stub PR 31 opened; CI Integration Tests still in progress
- No OPEN PR comments

### Rank-up moves
None.
