## Context

See proposal.md for why. `ServeHTTP` already implements the four contracts. The four-stack matrix runs only `scripts/integration-tests.Tests.ps1`. CRS whoami/drain origins do not return HTTP 5xx on `/protected`, so behaviour 4 needs a fixture origin. `/force-test` has no health tracker, so deny-verb-during-fail-open must use `/threshold-test`.

## Goals / Non-Goals

**Goals:**

- Four new Pester `It`s (handshake skip may be two Its under one Describe) in the matrix file.
- A 503 fixture the plugin can `Do` against, with a body marker the client must not see.
- Usage packet update if helpers, stacks, or compose routes change.

**Non-Goals:**

- Changing `pkg/modsecurity/serve.go` unless an It fails on current `main`.
- Joining `integration-tests.BodySize.Tests.ps1` to CI.
- Teaching CRS `deny,status:500` as sidecar-down.

## Decisions

1. **Land tests in `scripts/integration-tests.Tests.ps1`.** Alternative: a new file plus workflow path change. Rejected — explore assumed the matrix file CI already runs.

2. **503 fixture is nginx:alpine plus a committed `server { return 503 "sidecar-5xx-marker"; }` config, mounted read-only.** Alternative: CRS custom rule `deny,status:500`. Rejected — research (`knowledge/research/ext_modsecurity_http-status_deny-vs-error`) says that 500 is still a ModSecurity deny, not a proxy/crash 5xx. Alternative: `hashicorp/http-echo` — no reliable 503 body. Same labels in `docker-compose.test.yml` and `docker-compose.test.nginx.yml`. Drain overlays leave the service running.

3. **Backoff off on the 5xx route** so the client 502 is observable. Alternative: threshold 1 fail-open to whoami (200). That would hide a copy-503 bug if whoami also returned a body and we only checked status 200. 502 + marker-absent is the unique signal. Do **not** add this path to `Wait-ForAllServices` (it is never 2xx). Hit it after Traefik API readiness.

4. **Reuse `Invoke-TcpHttpRequest` for forged Upgrade and `Invoke-WebSocketEcho` for the real handshake.** URL-encode the SQL-injection query on the WebSocket URI. Add a helper only if those cannot send the request.

5. **Extend the existing `/threshold-test` Describe** for deny-verb-during-fail-open and backoff resume, each with try/finally `docker start` + `Wait-ForWafHealthy`. Resume waits > 10s after healthy (route `unhealthyWafBackOffPeriodSecs=10`). Alternative: a new middleware with backoff 2s. Rejected — extra compose surface; 12s sleep is acceptable for one It.

## Risks / Trade-offs

- [Backoff resume flake] → Mitigation: wait `Wait-ForWafHealthy` then `Start-Sleep` 12 seconds; assert 4xx not 200; `-Because` names backoff resume.
- [Forged Upgrade still 200 if CRS misses the probe] → Mitigation: same query string as existing `Test-MaliciousPatterns` SQL-injection pattern; assert status ≥ 400.
- [WebSocket query encoding vs CRS] → Mitigation: encode `id=1' OR '1'='1` in the URI; if skip is broken the handshake itself fails (403), which the It already treats as failure.
- [503 fixture not registered yet] → Mitigation: Traefik API is already in `Wait-ForAllServices`; retry the GET a few times if 404.
- [nginx alpine pull in CI] → Mitigation: small official image; both compose files use the same tag.

## Migration Plan

No operator deploy change. Rollback is revert of the test/compose commit.

## Open Questions

None. Remaining assumed rows live on `devstate/explore.md`.
