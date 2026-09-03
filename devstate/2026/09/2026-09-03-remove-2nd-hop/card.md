Developer review: in progress — 2026-09-03T04:40:10Z

## What this changes
**Operators.** Demo compose (`docker-compose.yml` / `docker-compose.local.yml`) mounts `crs-apache/httpd-vhosts.drain.conf` and no longer runs unlabeled `dummy`. CRS inspects a copy and answers 200; Traefik `next` is the app.

**Admin users.** None.

**Developers.** Four named test stacks remain: `apache-whoami`, `nginx-whoami`, `apache-drain`, `nginx-drain`. `./Test-Integration.ps1 -Stack` / `-AllStacks` and CI matrix cover all four. Pester prints `BENCH stack=` bombardier lines. Plugin `ServeHTTP` is unchanged.

**End users.** On drain/demo, `Range: bytes=10240-` is no longer copied as a sidecar 416 WAF block. Whoami test stacks still can 416 (dummy origin).

## Motivation
On main, every CRS inspect still `ProxyPass` / `proxy_pass` to unlabeled dummy whoami. That hop is not the real app, so dummy/whoami behavior (Range 416) is copied as a security block, operators confuse dummy with Traefik's backend, and every allow pays an extra origin round-trip. That extra hop is one slice of the long-standing WAF-path cost tracked upstream in [acouvreur/traefik-modsecurity-plugin#2](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/2) (bombardier: no-WAF ~14430 req/s vs WAF ~748 req/s, ~20x). Without this PR those false blocks stay, and we cannot compare dummy vs inspect-only on the same suite.

## Merge readiness
Implement landed four stacks + benches; CI on this head not seen yet. 2 items remain.

Priority: P2 — real operator pain from dummy/whoami (false 4xx blocks, extra hop), with a workaround of keeping dummy on whoami test stacks
Reviewed head: 13c19a0
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Pushed apply; CI on this head not seen |
| CI proof | 1/6 | not seen on 13c19a0 |
| Local tests proof | N/A | prHost github — CI proof covers remote |
| Review resolution | 6/6 | OPEN PR 31, no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-remove-2nd-hop pushed | `git` (push follows this card write) |
| OpenSpec | inspect-only-crs-sidecar | `openspec/changes/inspect-only-crs-sidecar/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/31 | GitHub |
| CI | not seen | not measured on this head yet |
| Local tests | passed | `./Test-Integration.ps1 -AllStacks -TestPath ./scripts/integration-tests.Tests.ps1` — all four stacks 0 failed (whoami 45 pass / 2 skip; drain 46 pass / 1 skip). Runner exit-code leak fixed; apache-drain bench-only re-run exit 0 |
| PR comments | no comments | no comments.md items |
| Security | None. | no `codereview.md` yet |
| Performance | See Agent review details — pinned to [acouvreur#2](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/2) | bombardier `-c 50 -d 15s` `/protected` |

## Specs
- [core_crs_sidecar_inspect-only](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-remove-2nd-hop/openspec/changes/inspect-only-crs-sidecar/proposal.md) — added

## Follow-up issues
- [ ] [note] [large] README `BenchmarkProtectedEndpoint` → no `Benchmark*` in this tree — README documents an integration bench that is not found. Not this ticket.

## How this fits together
Inspect-only CRS overlay is on branch `2026-09-03-remove-2nd-hop` as PR 31. Demo is drain-only; tests keep whoami + drain and bench all four. Throughput is the same class of measurement as [acouvreur#2](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/2) (bombardier on WAF vs non-WAF). This PR does not remove the WAF hop; it removes the dummy origin after CRS.

## Decision needed
None.

## Before merge
- [ ] [P3] Wait for CI on the four-stack matrix (bombardier installed in the workflow)
- [x] Keep apache+whoami, nginx+whoami, apache+drain, nginx+drain in the suite and bench all four
- [x] Overlay CRS inspect-only 200 on demo + drain stacks (nginx: loopback origin, not `return` on CRS `location /`)
- [x] Prove live CRS gates: GET+POST allow, URI block, POST-body block, Range not sidecar 416 on drain, dummy present only on whoami stacks

## Findings
None.

## Agent review details

### Security
None.

### Performance
Upstream pin: [Increase plugin performance (#2)](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/2) — bombardier, WAF path ~20x slower than no-WAF (748 vs 14430 req/s at `-c 125 -d 10s`). This ticket measures the **dummy origin hop inside the WAF path**, not WAF-off.

Before (explore, Apache whoami, `-c 50 -d 15s` `/protected`): GET 5077 req/s / 9.84 ms (76072 2xx / 125 5xx); POST 1098 req/s / 45.47 ms (12600 2xx / 3901 5xx).

After (same flags, this apply):

| Stack | GET req/s | GET latency | GET 2xx/5xx | POST req/s | POST latency | POST 2xx/5xx |
| --- | --- | --- | --- | --- | --- | --- |
| apache-whoami | 4999.25 | 10.00 ms | 74956 / 67 | 1149.90 | 43.44 ms | 12299 / 4995 |
| nginx-whoami | 3989.81 | 12.52 ms | 59894 / 0 | 1947.69 | 25.66 ms | 27451 / 1802 |
| apache-drain | 5211.54 | 9.60 ms | 78061 / 145 | 1348.95 | 37.02 ms | 17554 / 2727 |
| nginx-drain | 3588.45 | 13.93 ms | 53862 / 0 | 2552.73 | 19.57 ms | 38341 / 0 |

Apache drain vs explore whoami: GET ~+3% (noise), POST ~+23%. Nginx drain vs nginx whoami (same session): GET −10%, POST +31% and 0 5xx. CRS still dominates; dummy hop is not the 20x in #2.

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 1 added / 0 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 13c19a054bb9bcf11de533d8c8d0d3653b192258 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution vs main: inspect-only overlay for demo/drain; keep whoami stacks so #2-style bombardier can compare origins. Nginx drain is a loopback `server` after `proxy_pass` (`max_ranges 0`), not `return` on CRS `location /` (measured skip) and not serial `nc`.

Do we have a high-confidence way to reproduce? Yes — Pester `Allow-path throughput` plus `./Test-Integration.ps1 -AllStacks`.

Is this the best way to solve the issue? Yes vs DestBranch: overlay only, no plugin change, four-stack compare kept.

### Evidence
What I checked:
- nginx-drain and apache-drain smoke: GET 200, Range 200, URI 403, POST 200, POST SQLi 403, no dummy
- `./Test-Integration.ps1 -AllStacks` main Pester file: 0 failed on all four
- BENCH lines above (bombardier `-c 50 -d 15s`)
- Upstream [acouvreur#2](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/2) cited as the performance issue this measurement family belongs to

### Rank-up moves
- Absolute GET RPS on nginx-drain was slightly below nginx-whoami; treat as noise unless a second run repeats it.


