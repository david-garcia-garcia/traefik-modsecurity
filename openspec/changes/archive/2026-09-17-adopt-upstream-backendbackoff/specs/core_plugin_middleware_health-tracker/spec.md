## REMOVED Requirements

### Requirement: Omitted threshold and window use safe defaults
**Reason**: The health-tracker leaf named the deleted tumbling-window counter. Enablement defaults live on `core_plugin_middleware_waf-backoff`.
**Migration**: Use `core_plugin_middleware_waf-backoff` requirement "Omitted threshold uses five failures". Window 10 remains a Prepare default only.

### Requirement: Failure count tumbles with the window
**Reason**: The admission gate uses a credit budget, not a tumbling window.
**Migration**: Trip and refill rules are on `core_plugin_middleware_waf-backoff`.

### Requirement: Unhealthy WAF follows failMode for the backoff period
**Reason**: Skip-while-open and resume-via-probe replace "resume every request after the period".
**Migration**: Use `core_plugin_middleware_waf-backoff` requirements "Unhealthy WAF follows failMode for the cooldown" and "One sidecar probe after cooldown".

### Requirement: Backoff off leaves the tracker unused
**Reason**: The unused unit is the gate, not a tracker.
**Migration**: Use `core_plugin_middleware_waf-backoff` requirement "Backoff off leaves the gate unused".

### Requirement: Drain-stack suite proves backoff resume
**Reason**: Same Pester proof now belongs on the renamed leaf.
**Migration**: Use `core_plugin_middleware_waf-backoff` requirement "Drain-stack suite proves probe after cooldown".
