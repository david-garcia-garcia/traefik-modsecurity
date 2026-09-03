# Explore
IssueKey: 2026-09-03-improve-test-coverage

## Concepts

The CI matrix (`.github/workflows/integration-test.yml`) is four Compose stacks × one Pester file (`scripts/integration-tests.Tests.ps1`). Go unit tests already pin most `ServeHTTP` branches in `pkg/modsecurity/serve.go`. The ticket is the live wiring: Traefik labels, CRS (or a fixture sidecar), and what the client actually sees.

```
client ──► Traefik + plugin ──► sidecar (CRS or fixture)
                 │
                 ├── handshake skip ──► next (no sidecar)
                 ├── deny-verb body ──► 400 (even if tracker unhealthy)
                 ├── sidecar 3xx/4xx ──► copy block
                 ├── sidecar 5xx / transport ──► error; fail-open or 502
                 └── sidecar <300 ──► next
```

Critical means: if this branch regresses in production, operators either (a) skip the WAF for traffic that should be inspected, (b) fail-open past a client-fault reject, (c) never resume inspection after backoff, or (d) copy a sidecar 5xx as if it were a CRS block.

Existing live Its already cover CRS query/POST deny, Host/ClientHost on deny, fail-open *trip*, body 413, GET/HEAD/DELETE-with-body while the WAF is up, and a happy-path WebSocket echo. They do not pin the four below.

## Decisions

**The four behaviours** (this run will add Pester for these only):

1. **Handshake-only WAF skip (live).** Forged `Upgrade: websocket` without a `Connection` token `upgrade` on a CRS SQL-injection GET to `/protected` still returns 4xx (inspected). A real handshake to `/ws-echo` with that same probe in the query string still echoes (skipped). Helpers: `Invoke-TcpHttpRequest`, `Invoke-WebSocketEcho` in `scripts/TestHelpers.ps1`. Spec: `openspec/specs/core_plugin_middleware_websocket-skip/spec.md`. Unit already has `isWebsocket` cases in `pkg/modsecurity/upstream_issue_05_test.go` / `modsecurity_test.go`; those do not hit CRS or Traefik.

2. **Denied-verb body during fail-open.** After `/threshold-test` trips (threshold 3, same Its that already stop the WAF container), a GET with a body to `/threshold-test` still returns 400 and does not return whoami. `/force-test` has no health tracker (`unhealthyWafBackOffPeriodSecs` omitted). Spec: `openspec/specs/core_plugin_middleware_deny-verbs-with-body/spec.md`. Unit: `deny_verbs_with_body_test.go` `TestModsecurity_DefaultGetWithBodyIsRejectedWhenWAFUnhealthy`.

3. **Fail-open backoff resume.** After that trip, start WAF, `Wait-ForWafHealthy`, wait longer than `unhealthyWafBackOffPeriodSecs` (10s on `/threshold-test`), then a CRS SQL-injection GET to `/threshold-test` is 4xx again (sidecar consulted). If resume is broken the probe stays 200. Spec: `openspec/specs/core_plugin_middleware_health-tracker/spec.md` “When that period elapses, the plugin SHALL resume calling the sidecar.”

4. **Sidecar HTTP 5xx is not copied as a block.** CRS whoami/drain origins do not emit 5xx on `/protected`. Add a tiny fixture origin that returns HTTP 503 with a distinctive body, and a Traefik route whose `modSecurityUrl` points at it with backoff off (`unhealthyWafBackOffPeriodSecs` omitted / 0). Client SHALL receive 502, SHALL NOT receive 503 or that body, access log `X-Waf-Status` SHALL be `error`. Transport-fail `/error-test` cannot see a copied sidecar page. Spec: `openspec/specs/core_plugin_middleware_waf-status/spec.md` / `sidecar-response`. Research: `knowledge/research/ext_modsecurity_http-status_deny-vs-error/notes.md` (CRS `deny,status:500` is a different fact; this fixture is a down/proxy 503, not a CRS deny).

**How to land them:** new `It`s in `scripts/integration-tests.Tests.ps1` (the matrix file). New helpers only if an existing one cannot send the request. Mirror the 503 fixture + route labels in `docker-compose.test.yml` and `docker-compose.test.nginx.yml`. Drain overlays keep those services. Update `knowledge/devdocs/build_testing_integration.md` when the helpers/stacks change.

**Not in the four:** inbound cancel vs health (hard to abort mid-request in Pester; Go already has it); failure-window tumble (30s sleep in CI); OPTIONS/TRACE/CONNECT-with-body (same 400 gate as GET); allow-path CORS header copy (drain Hostname match already catches sidecar-*body* copy; header copy is unit-tested); plugin XFF no-append (audit ClientHost It plus Go); BodySize file joining the matrix.

No new ubiquitous language. Integration usage packet is enough to call the helpers; implement updates it if compose/helpers change.

## Open questions

- Q: Which four untested integration behaviours are most critical?
  Decision: resolved — (1) handshake-only WAF skip live, (2) deny-verb body during fail-open, (3) backoff resume, (4) sidecar 5xx not copied as a block. Reasons in Decisions.
  By: explore

- Q: Does behaviour 4 need a compose fixture, given CRS does not emit 5xx on `/protected`?
  Decision: assumed — yes; add a 503 origin with a distinctive body and a `/waf-5xx-test` (name may change) route with backoff off. Do not teach CRS `deny,status:500` as “sidecar down”.
  By: explore

- Q: Should `scripts/integration-tests.BodySize.Tests.ps1` join the CI matrix in this change?
  Decision: assumed — no; out of scope. The four land in the file CI already runs.
  By: explore

- Q: Who already owns client address / Host for these tests?
  Decision: resolved — Traefik owns `ClientHost` / `X-Real-Ip`; CRS trust rewrites `REMOTE_ADDR` from that. This change does not add an identity test and does not reconstruct IP from `RemoteAddr`.
  By: explore
