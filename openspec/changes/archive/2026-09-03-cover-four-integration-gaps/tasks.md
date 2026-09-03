## 1. 503 fixture

- [x] 1.1 Add a committed nginx config that listens on 80 and `return 503` with body `sidecar-5xx-marker`. Mount it on a `nginx:alpine` service in `docker-compose.test.yml` and `docker-compose.test.nginx.yml`.
- [x] 1.2 Add a whoami route (PathPrefix `/waf-5xx-test`) whose plugin `modSecurityUrl` is that service, `modSecurityStatusRequestHeader=X-Waf-Status`, and `unhealthyWafBackOffPeriodSecs` omitted. Do not add this path to `Wait-ForAllServices`.

## 2. Handshake-only skip (read `knowledge/devdocs/build_testing_integration.md` and `scripts/TestHelpers.ps1` first)

- [x] 2.1 In `scripts/integration-tests.Tests.ps1`, add an `It` that `Invoke-TcpHttpRequest` GET `/protected` with the existing SQL-injection query, `Upgrade: websocket`, and `Connection: close` (no `upgrade` token). Assert status ≥ 400 (`-Because`).
- [x] 2.2 Add an `It` that `Invoke-WebSocketEcho` to `ws://localhost:8000/ws-echo` with that probe URL-encoded in the query. Assert the echoed payload matches.

## 3. Fail-open deny-verb and backoff resume

- [x] 3.1 In the existing `/threshold-test` Describe, add an `It` that stops the WAF, trips threshold (reuse the existing three-failure pattern), then GET `/threshold-test` with a body via `Invoke-SafeWebRequest`. Assert HTTP 400. `try/finally` restart + `Wait-ForWafHealthy`.
- [x] 3.2 Add an `It` that trips fail-open, restarts WAF, waits healthy, sleeps longer than 10s, then GET `/threshold-test` with the SQL-injection query. Assert status ≥ 400 and not 200. Same `try/finally` restart.

## 4. Sidecar 5xx not copied

- [x] 4.1 Add an `It` that GET `/waf-5xx-test` via `Invoke-SafeWebRequest` (retry briefly on 404). Assert status 502, not 503, body does not contain `sidecar-5xx-marker`, and the latest Traefik access-log `X-Waf-Status` for that path is `error` (`Get-TraefikAccessLogEntries` / `Get-LastAccessLogEntryForPath`).

## 5. Usage packet

- [x] 5.1 Update `knowledge/devdocs/build_testing_integration.md` for the 503 fixture, `/waf-5xx-test`, and the new Its. Append `devstate/knowledge.md`.

## 6. Prove

- [x] 6.1 Delegate `run-tests integration` (or stack-by-stack `./Test-Integration.ps1`) so the new Its pass on at least one stack locally. Record `handoff.yaml` `localTests`.
