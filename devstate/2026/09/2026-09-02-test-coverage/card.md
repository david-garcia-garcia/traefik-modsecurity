Developer review: ready for review — 2026-09-02T19:29:41Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** `TestModsecurity_ServeHTTP` clones every row. `Prepare` has reject-negative cases for the remaining numeric fields. One Plugin core has a concurrent mixed-body `ServeHTTP` test. `.github/workflows/go.yml` Test is `go test -race -v ./...` (`build.yml` is unchanged).

**End users.** None.

## Motivation
Without this PR, two `TestModsecurity_ServeHTTP` rows share one `*http.Request` (the table still passes), several `Prepare` negatives have no test, and the body-pool `buf.Bytes()` alias has no concurrent mixed-size race guard on the PR.

## Merge readiness
All checks on PR 30 succeeded. Specs archived. Title is ready.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: 4244c4a
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | CI green, no open comments, tests landed |
| CI proof | 6/6 | All six checks succeeded https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33673283492 |
| Local tests proof | 6/6 | `go test -count=1 ./...` passed (local `-race` not run: no gcc/cgo) |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-02-test-coverage pushed | origin |
| OpenSpec | close-remaining-waf-test-gaps archived | `openspec/changes/archive/2026-09-02-close-remaining-waf-test-gaps/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/30 | pr-host |
| CI | build 33673283492 success https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33673283492 | Integration apache/nginx, lint, Build, build (`go.yml` `-race`), Test Runner Script Validation |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | inventory |
| Security | None. | devstate/codereview.md |
| Performance | None. | devstate/codereview.md |

## Specs
- [build_ci_github_go-test](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-02-test-coverage/openspec/changes/archive/2026-09-02-close-remaining-waf-test-gaps/proposal.md) — added
- [core_plugin_middleware_prepare-validation](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-02-test-coverage/openspec/changes/archive/2026-09-02-close-remaining-waf-test-gaps/proposal.md) — modified
- [core_plugin_middleware_body-pool](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-02-test-coverage/openspec/changes/archive/2026-09-02-close-remaining-waf-test-gaps/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
`report.md` holes that were still open on `origin/main` are now tested on PR 30. Most of the original ten were already closed before this branch.

## Decision needed
None.

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
| Specs in this PR | 1 added / 2 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | No comments |
| Reviewed head | 4244c4a3dbc53e9919b5c6f3ddd9c588a202efad | Matches pushed IssueKey |

### Stored data model
None.

### Technical review
Best possible solution: Tests and `go.yml -race` versus `origin/main`, no runtime change.

Do we have a high-confidence way to reproduce? Yes — the leftover holes were missing tests; they now exist and CI ran them including `-race`.

Is this the best way to solve the issue? Yes.

### Evidence
What I checked:
- `go test -count=1 ./...` passed locally
- PR 30 all six checks success on `4244c4a` (run 33673283492)
- `go.yml` Test is `go test -race -v ./...`

### Rank-up moves
None.
