# Test coverage

1. [hard] Critical path untested — `pkg/modsecurity/serve.go:54-58` — Allow deny with failMode open has no test that next runs or the client is 200; `assertFollowupUnhealthy` (`serve_test.go:437-445`) only checks `X-Waf-Status=unhealthy`; fail-close skip is covered by `TestPlugin_FailModeCloseUnhealthySkipReturns502`
   → After a trip with failMode open, assert the follow-up is HTTP 200 and next ran
   Status: done
   Argument: added TestPlugin_FailOpenUnhealthySkipCallsNext.
2. [hard] Edge case untested — `pkg/modsecurity/serve.go:43-48` — Allow on an already-canceled inbound ctx (design-named) has no test; `TestPlugin_InboundCancelDoesNotTripHealth` cancels only after the sidecar received the request
   → Assert a request whose context is already canceled returns 502, does not call the sidecar, and does not skip later requests
   Status: done
   Argument: added TestPlugin_AlreadyCanceledAllowDoesNotTripHealth.
3. [hard] Edge case untested — `pkg/modsecurity/plugin.go:151-153` — backoff 0 leaves the gate unused; `TestPlugin_WafFailureDefaultFailOpen` "without backoff" cases assert only the failing request
   → After a sidecar failure with backoff unset, assert a later request still reaches ModSecurityUrl
   Status: done
   Argument: added TestPlugin_BackoffOffStillCallsSidecarLater.
4. [judgement] Happy path only — `pkg/modsecurity/plugin.go:156-166` — explicit max cooldown and failure-ratio mapping arms have no ServeHTTP proof; `TestPrepare_AcceptsFailureRatioHalf` / `TestPrepare_RejectsMaxBackoffBelowBase` only accept or reject the knobs
   → Assert a set ratio or max changes trip or cooldown, or skip if Prepare validation is enough
   Status: skipped
   Argument: judgement; Prepare validation covers the knobs.
5. [judgement] Happy path only — `pkg/modsecurity/serve.go:49-52` — non-cancel Allow error follows failMode; (none)
   → Assert ServeHTTP after Gate Close fail-opens without a sidecar call, or skip if that life cycle is unreachable
   Status: skipped
   Argument: judgement; Close runs only when the reclaim incarnation ends.
