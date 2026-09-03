Developer review: in progress — 2026-09-03T04:00:43Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** CRS Docker BACKEND overlay notes landed under `knowledge/research/ext_modsecurity_crs-docker_backend/` (inspect-only vs `proxy_pass` / `ProxyPass`). No compose overlay yet.

**End users.** None.

## Motivation
On main, every CRS inspect still `ProxyPass` / `proxy_pass` to an unlabeled dummy whoami. That hop is not the real app, so a `Range` header or a small origin body can become a sidecar 416 that this plugin copies as a security block, and operators confuse dummy with Traefik’s backend. Without this PR those false blocks and the extra hop stay.

## Merge readiness
Explore reproduced the dummy hop and measured before-change throughput; the overlay is not implemented. 3 items remain.

Priority: P2 — real operator pain from dummy/whoami (false 4xx blocks, extra hop), with a workaround of keeping dummy
Reviewed head: 097fe53
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | CI green; product overlay still not in the diff |
| CI proof | 6/6 | All six checks succeeded |
| Local tests proof | N/A | Before implement (`localTests: none`) |
| Review resolution | 6/6 | OPEN PR 31, no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-remove-2nd-hop pushed | `git` |
| OpenSpec | none | `openspec list --json` empty changes |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/31 | GitHub list |
| CI | Integration Tests (apache) success https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33713007773/job/100516282906 ; Integration Tests (nginx) success https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33713007773/job/100516282957 ; Test Runner Script Validation success https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33713007773/job/100516282614 ; lint success https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33713007828/job/100516282863 ; build success https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33713007780/job/100516282702 ; Build success https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33713007978/job/100516283238 | pull_request_read get_check_runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | prepare inventory; no new comments this phase |
| Security | None. | no apply; no `codereview.md` |
| Performance | before: GET 5077 req/s (9.84 ms avg), POST 1098 req/s (45.47 ms avg); after not seen | bombardier -c 50 -d 15s, Apache `docker-compose.test.yml`, `http://localhost:8000/protected` |

## Specs
None.

## Follow-up issues
- [ ] [note] [large] README `BenchmarkProtectedEndpoint` → no `Benchmark*` in this tree — README documents an integration bench that is not found. Not this ticket.

## How this fits together
Local inspect-only sidecar spec is explored on branch 2026-09-03-remove-2nd-hop as PR 31 against main. Nginx `return 200` is rejected; Apache `/healthz` rewrite is the Apache path; after throughput still required.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Exact nginx drain listen port and entrypoint script name? | assumed — `127.0.0.1:18081`, script under `crs-nginx/` mounted into `/docker-entrypoint.d/`. Implement may pick a free high port if 18081 collides; keep loopback-only. | explore |

## Before merge
- [ ] Overlay CRS so the sidecar answers HTTP 200 after request phases; delete unlabeled `dummy` (nginx: drain-200, not `return`)
- [ ] Measure allow-path throughput after the overlay; put before (GET 5077 req/s, POST 1098 req/s), after, and delta on this card
- [ ] Prove live CRS gates: GET+POST allow, URI block, POST-body block, Range not sidecar 416, client-IP audit, no dummy service

## Findings
None.

## Agent review details

### Security
None.

### Performance
Before-change Apache allow-path (bombardier -c 50 -d 15s, `/protected`): GET 5077.24 req/s avg, 9.84 ms latency, 76072 2xx / 125 5xx; POST 1098.11 req/s avg, 45.47 ms latency, 12600 2xx / 3901 5xx. After not measured. Nginx `return 200` skips CRS (including URI probes) — do not ship it.

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 097fe536ee2548c05c1172f545d9c7ebce29b1cb | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: not implemented. DestBranch still proxies CRS to dummy whoami. Explore says Apache `/healthz` rewrite for inspect-only; nginx drain-200 on loopback.

Do we have a high-confidence way to reproduce? Yes — dummy running; Traefik `Range: bytes=10240-` → 416; WAF-direct GET body is dummy hostname `aa247ec7bea4` vs app `1d6f75bc6da6`; nginx return spike allowed SQLi with 200.

Is this the best way to solve the issue? Apache rewrite-200 matches the image’s own `/healthz` and still 403s body SQLi. Nginx `return` is not; drain-200 is the fallback the brief already named.

### Evidence
What I checked:
- `docker compose -f docker-compose.test.yml` up; dummy running
- GET `/protected` 200 (app whoami); URI SQLi 403; POST allow 200; POST body SQLi 403
- `Range: bytes=10240-` via Traefik and at `waf:8080/` → 416; Apache `/healthz` + Range also 416
- WAF-direct GET body is dummy whoami, not the app
- nginx throwaway `return 200` overlay: URI SQLi, traversal, POST SQLi all 200
- bombardier before numbers above
- CI all success on 097fe53

### Rank-up moves
None.
