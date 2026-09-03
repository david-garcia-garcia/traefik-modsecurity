Developer review: in progress — 2026-09-03T07:02:37.542Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None. This SHA only adds the ticket bus under `devstate/2026/09/2026-09-03-remove-dummy/`.

**End users.** None.

## Motivation
On main, demo compose is already inspect-only drain, but integration whoami stacks and README still run or document an unlabeled dummy CRS origin. That origin can return Range 416 or 304, which this plugin copies as a WAF block. Without this PR, tests and docs keep teaching the hop the demo already dropped.

## Merge readiness
Prepare complete; explore not started. 7 items remain.

Priority: P3 — tests and docs still teach dummy after demo already drain
Reviewed head: c53e7e4
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Stub PR opened; product apply not started |
| CI proof | 1/6 | Pushed; checks not seen yet |
| Local tests proof | N/A | Remote PR; implement has not run tests |
| Review resolution | 6/6 | No OPEN PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-remove-dummy pushed | `git` origin/2026-09-03-remove-dummy |
| OpenSpec | none | `openspec/` unchanged vs main |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/43 | pr-host Create |
| CI | not seen | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | no comments.md |
| Security | None. | no codereview.md |
| Performance | None. | no codereview.md |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local chat spec `remove-dummy` is branch `2026-09-03-remove-dummy` and stub PR 43 against main. Qualify is `qualified-with-gaps` (drain 304 unknown; four-stack CI not re-run in prepare).

## Decision needed
None.

## Before merge
- [ ] Explore whether drain Apache/nginx can still emit 3xx/4xx the plugin copies as a block
- [ ] If drain is robust, drop dummy from tests and docs; otherwise keep whoami stacks and record the gap

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
| Specs in this PR | none | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | c53e7e4999f7add2fdc61ce987f6c92845c5237d | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: not applicable yet vs main (bus only).

Do we have a high-confidence way to reproduce? Yes, dummy whoami stacks plus Range / If-Modified-Since against `modSecurityUrl`.

Is this the best way to solve the issue? Not decided. Prepare does not choose drain-only vs keep dummy.

### Evidence
What I checked:
- Demo compose mounts drain vhost and has no dummy (`docker-compose.yml`, `docker-compose.local.yml`)
- Test whoami stacks still set `BACKEND=http://dummy` (`docker-compose.test.yml`, `docker-compose.test.nginx.yml`)
- Drain overlays and CI four-stack matrix exist on `origin/main` (`6dae0ab`)
- Plugin copies 300–499 (`pkg/modsecurity/serve.go`)
- Qualify `qualified-with-gaps` (`handoff.yaml`)

### Rank-up moves
None.
