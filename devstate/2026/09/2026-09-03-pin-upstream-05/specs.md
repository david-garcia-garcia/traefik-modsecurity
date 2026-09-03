# Specs
change: pin-upstream-issue-05

verdicts:
  - { deltaId: handshake-detection-no-panic, fold, spec-id: core_plugin_middleware_websocket-skip, confidence: high, candidates: [core_plugin_middleware_websocket-skip, core_plugin_middleware_request-context] }
  - { deltaId: inbound-abort-no-nil-deref, fold, spec-id: core_plugin_middleware_request-context, confidence: high, candidates: [core_plugin_middleware_request-context, core_plugin_middleware_websocket-skip, core_plugin_middleware_deny-verbs-with-body] }

- modified core_plugin_middleware_websocket-skip
- modified core_plugin_middleware_request-context
