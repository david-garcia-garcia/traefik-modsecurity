Developer review: in progress — 2026-09-03T07:13:25.563Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None vs main product files. Explore recorded that nginx drain still 304s on `If-None-Match: *` until `proxy_pass` strips that header.

**End users.** None.

## Motivation
On main, demo compose is already inspect-only drain, but integration whoami stacks and README still run or document an unlabeled dummy CRS origin. That origin can return Range 416 or 304, which this plugin copies as a WAF block. Without this PR, tests and docs keep teaching the hop the demo already dropped.

## Merge readiness
Explore complete; propose not started. Dummy can go after nginx drain is hardened. 6 items remain.

Priority: P3 — tests and docs still teach dummy after demo already drain
Reviewed head: 61eefff
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Drain stacks pass CI; nginx `If-None-Match: *` still 304 locally |
| CI proof | 6/6 | All checks on run 33726328098 succeeded |
| Local tests proof | N/A | Remote PR |
| Review resolution | 6/6 | No OPEN PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-remove-dummy pushed | `git` origin/2026-09-03-remove-dummy |
| OpenSpec | none | product `openspec/` unchanged vs main |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/43 | pr-host |
| CI | build 33726328098 success https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33726328098 | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | no comments.md |
| Security | None. | no codereview.md |
| Performance | None. | no codereview.md |

## Specs
None.

## Follow-up issues
- [ ] [note] [large] Archive leftover `openspec/changes/inspect-only-crs-sidecar/` — tasks 15/15 on main, not moved to `archive/`. Not taken: separate catalog cleanup.

## How this fits together
Local chat spec is branch `2026-09-03-remove-dummy` and PR 43. Explore measured Apache drain as 200 on Range and conditionals; nginx drain 304s on `If-None-Match: *`. Dummy removal proceeds after that nginx harden.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Keep `crs-apache/httpd-vhosts.conf` (ProxyPass) as a sample? | assumed — delete with dummy stacks. Apache sample is `httpd-vhosts.drain.conf`. | explore |
| Archive leftover `openspec/changes/inspect-only-crs-sidecar/` in this ticket? | assumed — no. Fold the spec in a new change. Note as follow-up. | explore |

## Before merge
- [ ] Harden nginx drain `proxy_pass` so `If-None-Match` / `If-Modified-Since` cannot 304
- [ ] Drop dummy from tests, CI, and README; link drain sample files
- [P3] Confirm Pester covers Range and `If-None-Match: *` on both drain stacks

## Findings
- [P2] nginx drain `If-None-Match: *` is 304 — FIX — loopback `return 200` origin; plugin copies 304 as a block. Path: `crs-nginx/drain-origin.conf`. Reply none.

## Agent review details

### Security
None.

### Performance
None.

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 61eefff37574ce29b6290af391d6154aa2e70d9a | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: drain-only tests and docs, with nginx `proxy_set_header` clearing conditionals so sidecar stay 200 — vs main’s four-stack dummy+drain mix.

Do we have a high-confidence way to reproduce? Yes, nginx-drain + `If-None-Match: *` to `http://localhost:8000/protected` returned 304.

Is this the best way to solve the issue? Yes vs main: remove dummy after that harden; do not retune the plugin classifier.

### Evidence
What I checked:
- Apache drain sidecar/Traefik: GET/POST 200, SQLi 403, Range 200, If-Modified-Since 200, If-None-Match * 200 (local compose, 2026-09-03)
- Nginx drain: same except If-None-Match * → 304 sidecar and Traefik
- Throwaway nginx:alpine: `proxy_set_header If-None-Match ""` keeps 200; `etag off` does not
- CI four-stack success on bus-only head 61eefff (run 33726328098)

### Rank-up moves
None.
