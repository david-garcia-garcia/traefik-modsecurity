Developer review: in progress — 2026-09-03T04:05:06Z

## What this changes
**Operators.** None yet (overlay not applied). Compose still has dummy on main.

**Admin users.** None.

**Developers.** OpenSpec change `inspect-only-crs-sidecar` adds spec `core_crs_sidecar_inspect-only` (inspect-only CRS sidecar, no dummy origin). Plugin `ServeHTTP` is unchanged.

**End users.** None.

## Motivation
On main, every CRS inspect still `ProxyPass` / `proxy_pass` to an unlabeled dummy whoami. That hop is not the real app, so a `Range` header or a small origin body can become a sidecar 416 that this plugin copies as a security block, and operators confuse dummy with Traefik’s backend. Without this PR those false blocks and the extra hop stay.

## Merge readiness
Propose is apply-ready; overlay not implemented. 3 items remain.

Priority: P2 — real operator pain from dummy/whoami (false 4xx blocks, extra hop), with a workaround of keeping dummy
Reviewed head: c7f089c
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Apache integration tests still running on the explore commit |
| CI proof | 3/6 | Integration Tests (apache) in progress; nginx/lint/build succeeded |
| Local tests proof | N/A | Before implement (`localTests: none`) |
| Review resolution | 6/6 | OPEN PR 31, no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-remove-2nd-hop pushed | `git` |
| OpenSpec | inspect-only-crs-sidecar | `openspec/changes/inspect-only-crs-sidecar/` 4/4 artifacts |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/31 | GitHub |
| CI | Integration Tests (apache) in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33713575790/job/100517970039 ; Integration Tests (nginx) success https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33713575790/job/100517970082 ; Test Runner Script Validation success https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33713575790/job/100517969861 ; lint success https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33713575752/job/100517969655 ; build success https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33713575846/job/100517969970 ; Build success https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33713575778/job/100517969923 | pull_request_read get_check_runs |
| Local tests | none | handoff.yaml |
| PR comments | no comments | no comments.md items |
| Security | None. | no apply; no `codereview.md` |
| Performance | before: GET 5077 req/s (9.84 ms avg), POST 1098 req/s (45.47 ms avg); after not seen | bombardier -c 50 -d 15s, Apache test compose, `/protected` |

## Specs
- [core_crs_sidecar_inspect-only](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-remove-2nd-hop/openspec/changes/inspect-only-crs-sidecar/proposal.md) — added

## Follow-up issues
- [ ] [note] [large] README `BenchmarkProtectedEndpoint` → no `Benchmark*` in this tree — README documents an integration bench that is not found. Not this ticket.

## How this fits together
Inspect-only CRS sidecar is specified on branch 2026-09-03-remove-2nd-hop as PR 31. Implement applies Apache rewrite-200 and nginx drain-200, then re-benches.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Exact nginx drain listen port and entrypoint script name? | assumed — `127.0.0.1:18081`, script under `crs-nginx/` mounted into `/docker-entrypoint.d/`. Implement may pick a free high port if 18081 collides; keep loopback-only. | explore |

## Before merge
- [ ] Overlay CRS inspect-only 200; delete unlabeled `dummy` (nginx: drain-200, not `return`)
- [ ] Measure after throughput; put before (GET 5077 req/s, POST 1098 req/s), after, and delta on this card
- [ ] Prove live CRS gates: GET+POST allow, URI block, POST-body block, Range not sidecar 416, client-IP audit, no dummy

## Findings
None.

## Agent review details

### Security
None.

### Performance
Before-change Apache allow-path: GET 5077.24 req/s / 9.84 ms (76072 2xx, 125 5xx); POST 1098.11 req/s / 45.47 ms (12600 2xx, 3901 5xx). After not measured. Nginx `return 200` skipped CRS — design forbids it.

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 1 added / 0 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | c7f089c (working tree also has apply-ready OpenSpec) | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution vs main: not implemented. Spec + design: Apache `/healthz` rewrite; nginx loopback drain-200; unset Range.

Do we have a high-confidence way to reproduce? Yes — explore measured dummy hop, 416, and nginx return skipping CRS.

Is this the best way to solve the issue? Yes vs DestBranch: inspect-only overlay, no plugin change, no dummy.

### Evidence
What I checked:
- `openspec validate --changes --strict` passed for `inspect-only-crs-sidecar`
- FindSpecHost new `core_crs_sidecar_inspect-only` (not fold into plugin sidecar-request)
- Explore before-change bombardier numbers
- CI apache still in progress on explore commit

### Rank-up moves
None.
