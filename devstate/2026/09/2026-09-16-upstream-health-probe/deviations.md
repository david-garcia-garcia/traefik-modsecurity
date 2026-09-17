# Deviations

- [x] taken  credit plus half-open probe instead of the ask's tumbling-window counter
  Asked: replace pkg/health while preserving operator-visible WAF backoff (threshold in a window, then a fixed skip).
  Instead: upstream Gate credit budget, exponential cooldown capped to a fixed max by default, and one half-open probe after cooldown.
  Owner: `github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff`
  Why: honouring the letter would wrap Allow/Report as RecordFailure/IsUnhealthy and reimplement a window the gate does not have.
  By: explore
  Requester: not asked

- [x] taken  keep unhealthyWafFailureWindowSecs on Config but do not feed it to the gate
  Asked: map the three existing unhealthy JSON fields onto the upstream probe.
  Instead: window stays for Prepare defaults, negative rejection, and reclaim hash; trip uses TripFailures and credit.
  Owner: `pkg/modsecurity/config.go`
  Why: the gate has no tumbling window; dropping the JSON field would change pluginConfigHash for compose files that still set it.
  By: explore
  Requester: not asked

- [x] taken  drop Plugin.IsUnhealthy
  Asked: thorough coverage of the current tracker API (tests call IsUnhealthy).
  Instead: tests observe sidecar hit counts and modSecurityStatusRequestHeader.
  Owner: `pkg/modsecurity/serve.go`
  Why: Allow is not a peek; calling it to implement IsUnhealthy would consume the half-open probe.
  By: explore
  Requester: not asked

- [x] taken  Report success on admitted sidecar status below 500
  Asked: count WAF communication failures the way RecordFailure does today (failures only).
  Instead: Report(true) on 2xx/3xx/4xx so the credit budget can refill.
  Owner: `pkg/modsecurity/serve.go`
  Why: the gate contract is Report every admitted attempt; skipping success would leave credit stuck after mixed traffic.
  By: explore
  Requester: not asked
