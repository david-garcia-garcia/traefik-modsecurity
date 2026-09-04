Developer review: in progress — 2026-09-04T06:03:53Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Motivation
On `main`, a sidecar transport error or sidecar 5xx always calls the next handler. An operator who must not send traffic to the backend when ModSecurity cannot inspect the request has no plugin setting. Without this PR they stay fail-open.

## Merge readiness
Prepare grounded the ticket; product code is unchanged versus `main`. 7 items remain.

Priority: P2 — operator cannot fail-close when the WAF is down; current deploys keep fail-open
Reviewed head: fcb0e74
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI still running on the stub commit; no product apply yet |
| CI proof | 3/6 | in progress: [Test Runner Script Validation](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33842832474/job/100928435919), [Integration Tests (apache-drain)](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33842832474/job/100928435907), [Integration Tests (nginx-drain)](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33842832474/job/100928435715), [Build](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33842832483/job/100928435783), [build](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33842832493/job/100928435689), [lint](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33842832446/job/100928435637) |
| Local tests proof | N/A | `localTests: none`; remote CI is the proof axis |
| Review resolution | 6/6 | OPEN PR; no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-04-fail-open-close pushed | git / GitHub |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/45 | GitHub List/Create |
| CI | in progress [33842832474](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33842832474) [33842832483](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33842832483) [33842832493](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33842832493) [33842832446](https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33842832446) | GitHub check runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | GitHub comment list |
| Security | None. | no `devstate/codereview.md` yet |
| Performance | None. | no `devstate/codereview.md` yet |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local spec on IssueKey `2026-09-04-fail-open-close` is grounded in `requirement.md` (`qualified-with-gaps`). Branch and stub PR 45 are open against `main`. Product apply has not started.

## Decision needed
None.

## Before merge
- [ ] Add an operator setting so WAF communication failure can fail-close (default remains fail-open)
- [ ] Update specs that currently forbid HTTP 502 on WAF failure
- [ ] Green CI on the apply, not only this stub commit

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
| Reviewed head | fcb0e74d03b16a76b4fe98d9f5a7f48a9cb56a0a | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: not applicable yet versus `main` (prepare only).

Do we have a high-confidence way to reproduce? Yes, `TestPlugin_WafFailureNeverFailClosed` and `ServeHTTP` after sidecar 5xx / transport error.

Is this the best way to solve the issue? Not chosen yet; explore/propose next.

### Evidence
What I checked:
- `pkg/modsecurity/config.go` has no fail-open/fail-close field (read, `aa6714d`)
- `pkg/modsecurity/serve.go` fail-opens transport errors and sidecar 5xx to `next` (read, `aa6714d`)
- Stub PR https://github.com/david-garcia-garcia/traefik-modsecurity/pull/45 (GitHub Create)
- CI in progress on head `fcb0e74` (GitHub get_check_runs)

### Rank-up moves
None.
