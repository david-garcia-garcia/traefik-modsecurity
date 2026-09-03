Developer review: ready for review — 2026-09-03T06:24:55Z

## What this changes
**Operators.** Traefik plugin config now accepts `bypassRules` (`method` + `pathRegexp`). When `modSecurityStatusRequestHeader` is set, a match writes `bypassrule` and the sidecar is not called.

**Admin users.** None.

**Developers.** `compiledBypass` is one compiled regexp per HTTP method (path regexes concatenated with `|` after `(?:pattern)` grouping) plus an any-method fallback. `ServeHTTP` does one map get, then at most one `MatchString` on `req.URL.Path`.

**End users.** Requests that match a bypass rule reach the backend without ModSecurity inspection.

## Motivation
`origin/main` has no operator allowlist to skip the ModSecurity sidecar for selected method+path patterns. Without this PR, high-frequency or admin routes stay on the sidecar hop, or the operator must omit the middleware on a separate Traefik router.

## Merge readiness
Ready for review. 0 items remain.

Priority: P2 — real operator pain, with a workaround (separate router without the plugin)
Reviewed head: c134ba7
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | CI succeeded; no open PR comments |
| CI proof | 6/6 | all required checks succeeded on c134ba7 — https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33722648722 |
| Local tests proof | N/A | prHost remote |
| Review resolution | 6/6 | no PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-add-bypass-routes pushed | git |
| OpenSpec | bypass-rules (archived) | openspec/changes/archive/2026-09-03-bypass-rules/ |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/40 | pr-host |
| CI | build 100544834157 succeeded https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33722648722/job/100544834157 | pr-host CI (lint, Build, go test -race, integration apache/nginx whoami+drain, Test Runner Script Validation all succeeded) |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | comments: none |
| Security | None. | devstate/codereview.md |
| Performance | None. | devstate/codereview.md |

## Specs
- [core_plugin_middleware_bypass-rules](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-add-bypass-routes/openspec/changes/archive/2026-09-03-bypass-rules/proposal.md) — added
- [core_plugin_middleware_status-header](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-add-bypass-routes/openspec/changes/archive/2026-09-03-bypass-rules/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local ticket 2026-09-03-add-bypass-routes is OPEN PR #40. Change `bypass-rules` is archived. Delivery card is this PR summary.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Does "escaped" mean regexp.QuoteMeta of each pathRegexp, or `(?:pattern)` wrap before `|` join? | assumed — wrap with `(?:...)` only. QuoteMeta would literalize PathRegexp and break the fork surface. | explore |
| Where do path-only rules (empty method) live so lookup stays one map get? | assumed — merge those patterns into every method's combined regexp, and keep the same combined regexp on `anyMethod` for methods not in the map. | explore |
| Bypass vs WebSocket vs denyVerbsWithBody order? | assumed — bypass first. Matching requests skip local GET-with-body reject and skip websocket detection. Token is `bypassrule` even on a handshake that also matches. | explore |
| Spec host for the allowlist vs the status token? | assumed — new `core_plugin_middleware_bypass-rules`; fold `bypassrule` into existing `core_plugin_middleware_status-header`. | explore |
| Method matching case (`GET` vs `get`)? | assumed — uppercase at compile and lookup. | explore |
| Who already owns client address / user / tenant / Host / trust hop for this skip? | assumed — none of those facts. Match uses `req.Method` and `req.URL.Path` as net/http already parsed them. | explore |
| Should path match use URL.Path or RequestURI (query included)? | assumed — `req.URL.Path` only. Query string is not part of the path regexp. | explore |

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
| Specs in this PR | 1 added / 1 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | c134ba7191ef6f005d1140b9ff6dff34c3975c52 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: One map lookup of the request method to a single compiled regexp (joined path alternatives), not a linear scan of rules.

Do we have a high-confidence way to reproduce? Yes — `pkg/modsecurity/bypass_test.go` (match, miss, method-only, path-only, header token, invalid regexp, one regexp per verb) and `go test -race ./...` on this head.

Is this the best way to solve the issue? Yes versus DestBranch, which has no allowlist and would otherwise copy the fork's per-rule loop.

### Evidence
What I checked:
- `go test -race -count=3 ./...` passed in golang:1.24 (docker)
- GitHub checks on c134ba7: lint, Build, go `build` (test -race), integration apache/nginx whoami+drain, Test Runner Script Validation all succeeded (run 33722648722 and siblings)
- Codereview four-axis: Standards 4 hard applied; Spec / Security / Performance none

### Rank-up moves
None.
