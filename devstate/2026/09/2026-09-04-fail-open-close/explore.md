# Explore
IssueKey: 2026-09-04-fail-open-close

## Concepts

**Fail-open**: on a WAF communication failure, call `next` so the backend still serves the client.

**Fail-close**: on a WAF communication failure, do not call `next`; refuse the client with the same empty HTTP 502 this plugin already uses for `http.NewRequestWithContext` failure.

**WAF communication failure**: sidecar transport error (except inbound `Canceled`) or sidecar HTTP 5xx. Not a security block (3xx/4xx), not local 413, not `denyVerbsWithBody` 400, not bypass-rule skip.

```
                    ServeHTTP
                        │
         bypass / deny-verb-body / body-read
                        │
              already unhealthy? ──yes──┐
                        │ no            │
                   sidecar Do           │
                        │               │
              3xx/4xx copy (block)      │
                        │               │
         5xx or transport error         │
                        │               │
              failMode open ──► next (today’s default)
              failMode close ──► 502, no next
                                    ◄──┘
```

## Decisions

- Public knob is `failMode` string on `Config` (`json:"failMode,omitempty"`). Allowed values `open` and `close`. Omitted/empty/`open` keeps today’s fail-open. `close` fail-closes. Invalid values fail Prepare (same pattern as `logLevel`).
- Fail-close also covers the already-unhealthy skip. If that path still called `next`, fail-close would leak to the backend after the health tracker trips.
- Fail-close status is empty HTTP 502 (`http.Error(rw, "", 502)`), matching `NewRequestWithContext` failure. Status-header stays `error` on the failing request and `unhealthy` on the already-unhealthy skip.
- Default remains fail-open so existing deploys do not flip.
- Health tracker still `RecordFailure` on the failing request; inbound `Canceled` stays 502 and is still not a WAF failure.
- Specs that today SHALL fail-open and SHALL NOT 502 (`core_plugin_middleware_waf-status`, `core_plugin_middleware_health-tracker`) become conditional on `failMode`.
- Reproduce: `TestPlugin_WafFailureNeverFailClosed` and `serve.go` after Do error / sidecar 5xx already encode fail-open-only. Not a runtime reproduce this session; those tests are the path.

## Open questions

- Q: What is the public field shape?
  Decision: decided — `failMode` string, `open` or `close`, default `open`. Invalid values fail Prepare.
  By: human

- Q: Does fail-close apply to the already-unhealthy skip (today always `next`)?
  Decision: assumed — yes; otherwise fail-close is bypassed after the tracker trips.
  By: explore

- Q: What does the client receive on fail-close?
  Decision: assumed — empty HTTP 502, same as existing plugin-owned 502s. Status-header `error` or `unhealthy` as today.
  By: explore
