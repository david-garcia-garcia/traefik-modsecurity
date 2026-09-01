## Context

See proposal.md — Why. `Plugin.ServeHTTP` builds the sidecar request at `pkg/modsecurity/serve.go` with `http.NewRequest`. Official `net/http` docs: that wraps `NewRequestWithContext` using `context.Background()`. `http.Client.Timeout` (`timeoutMillis`) is set in `pkg/modsecurity/plugin.go` and stays.

Research: `knowledge/research/ext_http_client_request-context/`.

## Goals / Non-Goals

**Goals:**

- Tie the sidecar request lifetime to the inbound `req.Context()`.
- Keep `timeoutMillis` as a hard cap when the inbound context stays live.
- Prove cancel-while-blocked with a unit test.

**Non-Goals:**

- Changing `MaxConnsPerHost`, idle pool, or drain behavior.
- Treating `context.Canceled` as a non-failure on the health tracker.

## Decisions

### Bind with `NewRequestWithContext`, not `Request.WithContext`

Use `http.NewRequestWithContext(req.Context(), req.Method, url, bodyReader)` at the existing construction site. `WithContext` is a shallow copy after the fact; the constructor is the documented API for an outgoing client request.

Alternatives considered: wrap after `NewRequest` via `proxyReq.WithContext(req.Context())`. Same result, extra allocation, deprecated-feeling path. Rejected.

### Keep `http.Client.Timeout`

The inbound context may have no deadline (or a long one). `timeoutMillis` remains the plugin's own cap. Go takes the earlier of context done and client timeout.

Alternatives considered: drop `Client.Timeout` and rely only on inbound deadlines. Rejected — Traefik may not always set a deadline that matches `timeoutMillis`.

### Unit test, not integration

Cancel the inbound context while a mock WAF blocks in `httptest`. Assert `ServeHTTP` returns before the configured timeout and the mock handler does not complete. Existing helpers in `pkg/modsecurity/serve_test.go` are enough; no Pester suite.

Alternatives considered: Docker/Pester disconnect. Heavier than the behavior needs. Rejected.

## Risks / Trade-offs

- [Risk] After the bind, a client disconnect makes `httpClient.Do` return an error and today's path calls `healthTracker.RecordFailure`. → Accepted for this change. Parked as `devstate/issues.md` note large. Mitigation: do not change health classification here.
- [Risk] Tests that use a canceled context by accident could start failing. → Incoming tests use live `httptest.NewRequest` contexts. No change expected.

## Migration Plan

No config or API migration. Deploy the new plugin version. Rollback is revert of the one construction-site change.
