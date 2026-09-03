# Specs
change: pin-keepass-webdav-put-tests

FindSpecHost:
verdicts:
  - { deltaId: deny-verbs-put-forward, fold, spec-id: core_plugin_middleware_deny-verbs-with-body, confidence: high, candidates: [core_plugin_middleware_deny-verbs-with-body, core_plugin_middleware_body-pool] }
  - { deltaId: sidecar-4xx-copy-on-put, fold, spec-id: core_plugin_middleware_sidecar-response, confidence: high, candidates: [core_plugin_middleware_sidecar-response, core_plugin_middleware_waf-status] }

- added (delta / fold) core_plugin_middleware_deny-verbs-with-body
- added (delta / fold) core_plugin_middleware_sidecar-response
