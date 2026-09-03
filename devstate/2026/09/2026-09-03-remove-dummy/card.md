Developer review: in progress — 2026-09-03T14:14:37Z

## What this changes
**Operators.** Drop unlabeled `dummy` / `BACKEND=http://dummy`. Mount [crs-apache/httpd-vhosts.drain.conf](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-remove-dummy/crs-apache/httpd-vhosts.drain.conf) for Apache CRS, or [crs-nginx/drain-origin.conf](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-remove-dummy/crs-nginx/drain-origin.conf) plus [crs-nginx/proxy_backend.drain.conf.template](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-remove-dummy/crs-nginx/proxy_backend.drain.conf.template) and [crs-nginx/realip.conf](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-remove-dummy/crs-nginx/realip.conf) for nginx (in-process origin on `unix:/tmp/modsecurity/crs-drain.sock`; no `BACKEND` env).

**Admin users.** None.

**Developers.** Integration is `apache-drain` / `nginx-drain` only. Pester asserts no `*-dummy-1`, Range not 416, and `If-None-Match: *` / `If-Modified-Since` not 304. Spec `core_crs_sidecar_inspect-only` describes the inspect-only sidecar. Both OpenSpec changes are archived; no active `openspec/changes/` folders. Plugin sidecar 3xx/4xx copy is unchanged.

**End users.** A client `Range` or `If-None-Match: *` on a WAF-protected route is no longer copied as a security block from a sidecar 416/304.

## Motivation
On main, demo compose is already inspect-only, but test compose and README still ran or taught unlabeled dummy as the CRS `BACKEND`. That hop can return Range 416 or nginx `If-None-Match: *` 304, which this plugin copies as a security block. Without this PR, operators who copy the test stack keep shipping those false blocks.

## Merge readiness
Product and OpenSpec archive cleanup landed on `25f71e9`; local integration suites passed; CI on this head is pending. 1 item remains.

Priority: P2 — false WAF blocks from sidecar 416/304 on routes using this plugin
Reviewed head: 25f71e9
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Product applied; remote CI pending on new head |
| CI proof | 3/6 | Commit status pending on `25f71e9` (no run URL yet) |
| Local tests proof | N/A | Remote PR; CI proof is the remote axis |
| Review resolution | 6/6 | No OPEN PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-03-remove-dummy pushed | `git` origin/2026-09-03-remove-dummy @ `25f71e9` |
| OpenSpec | archived (no active changes) | `archive/2026-09-03-remove-dummy-crs-origin`, `archive/2026-09-03-inspect-only-crs-sidecar` |
| Pull request | https://github.com/david-garcia-garcia/traefik-modsecurity/pull/43 | pr-host |
| CI | pending on `25f71e9` (not seen URL) | GitHub commit status |
| Local tests | passed | handoff.yaml localTests; apache-drain 57/57; nginx-drain 58/58 |
| PR comments | no comments | no comments.md |
| Security | None. | codereview.md |
| Performance | None. | codereview.md |

## Specs
- [core_crs_sidecar_inspect-only](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-remove-dummy/openspec/changes/archive/2026-09-03-remove-dummy-crs-origin/proposal.md) — added (catalog baseline was missing on main)
- [core_crs_sidecar_inspect-only](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/2026-09-03-remove-dummy/openspec/changes/archive/2026-09-03-remove-dummy-crs-origin/proposal.md) — modified (inspect-only sidecar; drop whoami dummy stacks)

## Follow-up issues
None.

## How this fits together
Chat ticket `remove-dummy` on branch `2026-09-03-remove-dummy`, stub PR 43 from prepare. Head `25f71e9` includes inspect-only sidecar apply, unix-socket nginx origin, and archive of both `remove-dummy-crs-origin` and leftover `inspect-only-crs-sidecar`. CI is pending on that head.

## Decision needed
None.

## Before merge
- [ ] Wait for PR 43 CI to succeed on `25f71e9`
- [x] Nginx sidecar public `:8080` stays 200 on `If-None-Match: *` (4.3.0 `proxy_pass` overlay)
- [x] Dummy service removed from test compose, CI matrix, and README
- [x] Leftover `inspect-only-crs-sidecar` archived to `openspec/changes/archive/2026-09-03-inspect-only-crs-sidecar/`

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
| Reviewed head | 25f71e9d20b2510b811fa37c1ea1b73a59721913 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Inspect-only sidecar on both engines, with nginx omitting conditional headers on `proxy_pass` to an in-process unix-socket `return 200` origin so CRS phases still run, instead of proxying to a separate origin container or changing the plugin’s 3xx/4xx copy rule.

Do we have a high-confidence way to reproduce? Yes, Pester on `/protected` for Range, `If-None-Match: *`, `If-Modified-Since`, URI/POST CRS denies, and `Get-DummyContainerName` empty; sidecar wget on `:8080` with `If-None-Match: *` returned 200.

Is this the best way to solve the issue? Yes versus main: a separate CRS `BACKEND` was the source of non-security 3xx/4xx; inspect-only sidecar plus header omit keeps CRS seeing client headers on the public listener.

### Evidence
What I checked:
- `go test ./...` passed after merge
- `./Test-Integration.ps1 -Stack apache-drain`: 57 passed, 0 failed; BENCH GET rps=5266.67 POST rps=1345.27 (POST xx5=1305 under bombardier)
- `./Test-Integration.ps1 -Stack nginx-drain`: 58 passed, 0 failed; BENCH GET rps=4032 POST rps=2848 (unix socket origin)
- nginx WAF start: healthy; public `:8080` `If-None-Match: *` → 200
- `25f71e9` pushed; archived leftover `inspect-only-crs-sidecar`; CI commit status pending

### Rank-up moves
- Apache drain POST bombardier logged 1305 HTTP 5xx at `-c 50`; the It only asserts req/s > 0. Not a dummy-removal blocker.
