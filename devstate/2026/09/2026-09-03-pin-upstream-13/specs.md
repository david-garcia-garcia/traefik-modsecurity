# Specs
change: pin-upstream-authelia-405

verdicts:
  - { deltaId: sidecar-405-copy, fold, spec-id: core_plugin_middleware_sidecar-response, confidence: high, candidates: [core_plugin_middleware_sidecar-response] }
  - { deltaId: sidecar-firstfactor-headers, fold, spec-id: core_plugin_middleware_sidecar-request, confidence: high, candidates: [core_plugin_middleware_sidecar-request] }

- modified core_plugin_middleware_sidecar-response
- modified core_plugin_middleware_sidecar-request
- archived 2026-09-03-pin-upstream-authelia-405 (fold sync landed on those baseline specs)
