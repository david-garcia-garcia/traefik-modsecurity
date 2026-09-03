Developer review: ready for review — 2026-09-03T20:21:16.094Z

## What this changes
**Operators.** WAF failures always fail-open to `next` (never HTTP 502 for sidecar down/5xx). `unhealthyWafBackOffPeriodSecs` only skips later sidecar calls after threshold; each failed attempt still fail-opens.

**Admin users.** None.

**Developers.** Pooled inbound bodies alias `buf.Bytes()` behind a two-consumer `doneReadCloser` gate; `defer` Closes both after `next`. Chunked bodies over the pool cap Put the checkout buffer and own the overflow. Specs/README match fail-open. Go lifecycle tests + `/chain-retry` / `/chain-buffer` Pester cover omit-Close and middleware mix.

**End users.** None.

## Motivation
On `main`, Put of a pooled body buffer can overwrite another request's POST while a sidecar or `next` reader still aliases those bytes. Without this PR that cross-request body corruption stays in production.

## Merge readiness
Ready for review. 0 items remain.

Priority: P1 — Production is unsafe, losing data, or serving a wrong public contract today
Reviewed head: 1d05fd1
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Head CI check-runs succeeded; local apache-whoami Pester green; no open PR comments |
| CI proof | 6/6 | Go `-race`, Build, lint, runner validation, apache-drain, nginx-drain success on 1d05fd1 https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33801197853 |
| Local tests proof | N/A | `prHost` is github |
| Review resolution | 6/6 | OPEN PR; comment inventory empty |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-pooled-body-race pushed | `git` 1d05fd1 |
| OpenSpec | pooled-body-alias-copy-out archived; body-pool + fail-open specs updated on branch | `openspec/changes/archive/2026-09-03-pooled-body-alias-copy-out/`; `openspec/specs/...` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/44 | pr-host |
| CI | build 33801197853 success (Go -race); integration 33801197871 success (drain stacks + validation) https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33801197871 | pr-host check_runs; whoami matrix arms did not schedule on this head (see Follow-up) |
| Local tests | passed | `go test -count=1 ./...`; `Test-Integration.ps1 -Stack apache-whoami` 59 passed / 0 failed / 2 skipped (includes chain-retry/buffer) |
| PR comments | no comments | inventory empty |
| Security | None. | prior codereview.md; gate prevents Put-while-Read |
| Performance | None. | bounded LimitReader; no copy-out on pooled path |

## Specs
- [core_plugin_middleware_body-pool](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-pooled-body-race/openspec/changes/archive/2026-09-03-pooled-body-alias-copy-out/proposal.md) — modified
- [core_plugin_middleware_waf-status](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-pooled-body-race/openspec/specs/core_plugin_middleware_waf-status/spec.md) — modified
- [core_plugin_middleware_health-tracker](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-pooled-body-race/openspec/specs/core_plugin_middleware_health-tracker/spec.md) — modified
- [core_plugin_middleware_sidecar-response](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-pooled-body-race/openspec/specs/core_plugin_middleware_sidecar-response/spec.md) — modified
- [core_plugin_middleware_log-level](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-pooled-body-race/openspec/specs/core_plugin_middleware_log-level/spec.md) — modified

## Follow-up issues
- [ ] [note] [small] Actions Integration Tests matrix on recent PR 44 heads only scheduled apache-drain + nginx-drain (whoami arms absent) while the workflow file still lists four stacks. Local apache-whoami covered chain routes. Investigate scheduling.

## How this fits together
PR 44 started as copy-out; product path is now `doneReadCloser` + defer Close + bounded chunked overflow + unconditional fail-open. Pushed `1d05fd1`; Go `-race` and scheduled integration jobs green; local whoami Pester green.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Copy-out or wait until consumers finish? | assumed — gate Put until both `doneReadCloser` consumers Close (defer after next); no copy-out on the pooled path. | chat |
| Fail-open vs HTTP 502 on WAF failure? | assumed — always fail-open to next; never 502 for WAF failure. Specs/README updated. | chat |
| Yaegi SetFinalizer inert? | assumed — comment only; production uses compiled Traefik plugins. Close on every exit is the release path. | chat |
| Local `go test -race` on this Windows agent? | assumed — not available (`CGO_ENABLED=0`). CI Linux ran `-race`. | explore |

## Before merge
None.

## Findings
None.

## Agent review details

### Security
None. Put cannot run while a live consumer still Reads under `doneReadCloser.mu`; after Close, Read returns `ErrBodyReadAfterClose` without touching the slice.

### Performance
None. Pooled path avoids copy-out; chunked overflow Puts the bounded checkout buffer.

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 5 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 1d05fd13bee269f7673fdcb2756cb209d79f3409 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution vs DestBranch: delay Put with a two-consumer gate instead of copy-out (keeps pool win) and Close both consumers via defer.

Do we have a high-confidence way to reproduce? Yes. Alias hold-RoundTripper test; Put-count tests for empty/allow/5xx/Transport omit-Close/chunked overflow; Close-mu deadlock test.

Is this the best way to solve the issue? Yes vs DestBranch copy-out-or-leak. Defer Close is the right shape once Close is idempotent.

### Evidence
What I checked:
- `go test -count=1 ./...` passed after defer refactor
- Local `Test-Integration.ps1 -Stack apache-whoami`: 59 passed, 0 failed (chain-retry concurrent POSTs included)
- CI Go `-race` https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33801197853
- CI Integration https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33801197871 (drain + validation)

### Rank-up moves
None.
