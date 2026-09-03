Developer review: in progress — 2026-09-03T07:23:35.230Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Research notes for `Client.Do` request-body lifetime and `bytes.Buffer.Bytes` aliasing; explore recorded a measured 1 MiB cross-request body leak.

**End users.** None.

## Motivation
On `main`, a pooled inbound-body buffer is Put when `ServeHTTP` returns while a sidecar RoundTripper may still read the aliased bytes. A later request can overwrite that array. Without this PR, one tenant's POST can appear as another tenant's WAF body.

## Merge readiness
Leak reproduced; product test and copy-out not landed. 6 items remain.

Priority: P1 — Production is unsafe, losing data, or serving a wrong public contract today
Reviewed head: 533b9e6
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI still running; no production code change |
| CI proof | 3/6 | Checks in progress on PR 44 after explore push |
| Local tests proof | N/A | Before implement |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-pooled-body-race pushed | `git` 533b9e6 |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/44 | pr-host |
| CI | build 33727841488 in progress https://github.com/david-garcia-garcia/traefik-modsecurity/actions/runs/33727841488 | pr-host check_runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | inventory empty |
| Security | None. | no codereview.md yet |
| Performance | None. | no codereview.md yet |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local ticket `2026-09-03-pooled-body-race` on a dedicated worktree, PR 44. Explore measured a full 1 MiB `0xBB` overwrite of a prior `0xAA` POST after Put. Next is propose (copy-out + RoundTripper regression), then implement lands the failing test before the fix.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Copy-out or wait until the sidecar body is consumed? | assumed — copy-out before any transport owns the slice. Waiting on Close/`next` does not match writeLoop / RoundTripper lifetime. | explore |
| Should the regression test use a real `http.Transport` 403-without-read? | assumed — no, not as the pass/fail assertion. persistConn closes the conn so the wire never shows the second request's bytes. Use a RoundTripper that holds Body until after Put. | explore |
| Who already owns client address, user, tenant, Host, or trust hop for this change? | assumed — none. This change does not set or reconstruct those fields. | explore |
| Spec host for the new invariant? | assumed — fold onto `core_plugin_middleware_body-pool`. Propose confirms with FindSpecHost. | explore |
| Local `go test -race` on this Windows agent? | assumed — not available (`CGO_ENABLED=0`). Semantic leak test is the local proof; CI `-race` if the workflow already runs it. | explore |

## Before merge
- [ ] [P1] Land a test that fails on current `main` by reproducing the 1 MiB `0xAA`→`0xBB` leak, then copy-out so the pooled array cannot escape into `net/http`
- [x] Stub PR 44 opened
- [x] Leak reproduced on this worktree (throwaway RoundTripper test, then deleted)

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
| Reviewed head | 533b9e682d58daf3ac8505d92e9c5de20eb52847 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: copy-out of `buf.Bytes()` before sidecar/`next` readers; Put the buffer after the copy.

Do we have a high-confidence way to reproduce? Yes. Throwaway test: first sidecar read after Put was 1048576 bytes of the second POST (`0xBB`), zero `0xAA`.

Is this the best way to solve the issue? Yes vs DestBranch: copy-out is the smallest fix that matches the RoundTripper contract. Waiting on `resp.Body.Close` does not wait for writeLoop.

### Evidence
What I checked:
- Throwaway `go test -count=1 -timeout 30s -v ./pkg/modsecurity -run TestThrowaway_PooledBodyCrossRequestLeak` FAIL: `0xAA=0 0xBB=1048576` (worktree, then file deleted)
- Real `http.Transport` 403-without-read did not show `0xBB` on the wire (`pc.close` after `wroteRequest` 50 ms)
- `knowledge/research/ext_http_client_request-body-lifetime/` and `ext_golang_bytes_buffer-bytes/`
- PR 44 CI in progress (run 33727841488)

### Rank-up moves
None.
