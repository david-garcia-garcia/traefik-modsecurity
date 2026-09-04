# Specs
change: cover-four-integration-gaps

FindSpecHost:
- { deltaId: handshake-skip-live, fold, spec-id: core_plugin_middleware_websocket-skip, confidence: high, candidates: [core_plugin_middleware_websocket-skip] }
- { deltaId: deny-verb-fail-open-live, fold, spec-id: core_plugin_middleware_deny-verbs-with-body, confidence: high, candidates: [core_plugin_middleware_deny-verbs-with-body] }
- { deltaId: backoff-resume-live, fold, spec-id: core_plugin_middleware_health-tracker, confidence: high, candidates: [core_plugin_middleware_health-tracker] }
- { deltaId: sidecar-5xx-not-copied-live, fold, spec-id: core_plugin_middleware_waf-status, confidence: high, candidates: [core_plugin_middleware_waf-status, core_plugin_middleware_sidecar-response] }

- modified core_plugin_middleware_websocket-skip
- modified core_plugin_middleware_deny-verbs-with-body
- modified core_plugin_middleware_health-tracker
- modified core_plugin_middleware_waf-status
