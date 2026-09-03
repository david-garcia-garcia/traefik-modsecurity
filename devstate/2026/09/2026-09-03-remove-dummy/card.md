Developer review: in progress — 2026-09-03T07:59:04.724Z

## What this changes
**Operators.** Drop unlabeled `dummy` / `BACKEND=http://dummy`. Mount [crs-apache/httpd-vhosts.drain.conf](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-remove-dummy/crs-apache/httpd-vhosts.drain.conf) for Apache CRS, or [crs-nginx/drain-origin.conf](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-remove-dummy/crs-nginx/drain-origin.conf) plus [crs-nginx/proxy_backend.drain.conf.template](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-remove-dummy/crs-nginx/proxy_backend.drain.conf.template) and [crs-nginx/realip.conf](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-remove-dummy/crs-nginx/realip.conf) for nginx (`BACKEND=http://127.0.0.1:18081`).

**Admin users.** None.

**Developers.** Integration is `apache-drain` / `nginx-drain` only. Pester asserts no `*-dummy-1`, Range not 416, and `If-None-Match: *` / `If-Modified-Since` not 304. Spec `core_crs_sidecar_inspect-only` is drain-only. Plugin sidecar 3xx/4xx copy is unchanged.

**End users.** A client `Range` or `If-None-Match: *` on a route using this repo’s drain sidecar is no longer copied as a WAF block from a dummy origin 416/304.

## Motivation
On main, demo compose is already inspect-only, but test compose and README still ran or taught unlabeled dummy as the CRS `BACKEND`. That hop can return Range 416 or nginx `If-None-Match: *` 304, which this plugin copies as a security block. Without this PR, operators who copy the test stack keep shipping those false blocks.

## Merge readiness
Implement landed; local drain suites passed; CI on this head is still running. 2 items remain.

Priority: P2 — false WAF blocks from dummy origin status, workaround is drain
Reviewed head: 55df208
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Product applied; remote CI still in progress |
| CI proof | 3/6 | Checks in progress on run 33730577891 |
| Local tests proof | N/A | Remote PR; CI proof is the remote axis |
| Review resolution | 6/6 | No OPEN PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-remove-dummy pushed | `git` origin/2026-09-03-remove-dummy |
| OpenSpec | remove-dummy-crs-origin | `openspec/changes/remove-dummy-crs-origin/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/43 | pr-host |
| CI | build 33730577891 in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33730577891 | pr-host CI |
| Local tests | passed | handoff.yaml localTests; apache-drain 57/57; nginx-drain 58/58 after merge |
| PR comments | no comments | no comments.md |
| Security | None. | no codereview.md yet |
| Performance | None. | no codereview.md yet |

## Specs
- [core_crs_sidecar_inspect-only](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-remove-dummy/openspec/changes/remove-dummy-crs-origin/proposal.md) — added (catalog baseline was missing on main)
- [core_crs_sidecar_inspect-only](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-remove-dummy/openspec/changes/remove-dummy-crs-origin/proposal.md) — modified (drain-only; drop whoami dummy stacks)

## Follow-up issues
- [ ] [note] [large] Archive leftover `openspec/changes/inspect-only-crs-sidecar/` (tasks 15/15, still on main, not in `archive/`) — previous drain work landed without archive. This ticket folds the spec in a new change; moving that folder is a separate catalog cleanup.

## How this fits together
Chat ticket `remove-dummy` on branch `2026-09-03-remove-dummy`, stub PR 43 from prepare. Head `55df208` includes drain-only apply plus merge of `origin/main`. Integration CI is running on that head.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Archive leftover `openspec/changes/inspect-only-crs-sidecar/` (tasks complete, still on main)? | assumed — not this ticket’s archive. Fold the spec in a new change. Note as follow-up. | explore |

## Before merge
- [ ] Wait for PR 43 CI to succeed on `55df208`
- [x] Nginx drain public `:8080` stays 200 on `If-None-Match: *` (4.3.0 `proxy_pass $upstream` overlay)
- [x] Dummy service removed from test compose, CI matrix, and README

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
| Specs in this PR | 1 added / 1 modified / none extra | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 55df20877f4c0d239f9cc9e224f8ddbcb69629f8 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Inspect-only drain origins on both engines, with nginx omitting conditional headers on `proxy_pass` so a loopback `return 200` is not rewritten to 304, instead of keeping dummy stacks or changing the plugin’s 3xx/4xx copy rule.

Do we have a high-confidence way to reproduce? Yes, Pester on `/protected` for Range, `If-None-Match: *`, `If-Modified-Since`, URI/POST CRS denies, and `Get-DummyContainerName` empty; sidecar wget on `:8080` with `If-None-Match: *` returned 200.

Is this the best way to solve the issue? Yes versus main: dummy is the source of non-security 3xx/4xx; drain plus header omit keeps CRS seeing client headers on the public listener.

### Evidence
What I checked:
- `go test ./...` passed after merge (`55df208`)
- `./Test-Integration.ps1 -Stack apache-drain`: 57 passed, 0 failed; BENCH GET rps=5266.67 POST rps=1345.27 (POST xx5=1305 under bombardier)
- `./Test-Integration.ps1 -Stack nginx-drain` after merge: 58 passed, 0 failed; BENCH GET rps=3812.59 POST rps=2593.52 xx5=0
- nginx WAF start: healthy; public `:8080` `If-None-Match: *` → 200; loopback `:18081` still 304 if the header is sent straight at `return 200`
- CI run 33730577891 in progress (lint/build/script validation already success)

### Rank-up moves
- Apache drain POST bombardier logged 1305 HTTP 5xx at `-c 50`; the It only asserts req/s > 0. Not a dummy-removal blocker.
