# Specs
change: waf-fail-closed
- added core_plugin_middleware_fail-closed
- modified core_plugin_middleware_waf-status
- modified core_plugin_middleware_health-tracker
- modified core_plugin_middleware_log-level
- modified core_plugin_middleware_sidecar-response

FindSpecHost:
- { deltaId: fail-closed-config, new, spec-id: core_plugin_middleware_fail-closed, confidence: high, candidates: [core_plugin_middleware_log-level, core_plugin_middleware_waf-status] }
- { deltaId: waf-status-fail-close, fold, spec-id: core_plugin_middleware_waf-status, confidence: high, candidates: [core_plugin_middleware_waf-status] }
- { deltaId: health-tracker-fail-close, fold, spec-id: core_plugin_middleware_health-tracker, confidence: high, candidates: [core_plugin_middleware_health-tracker] }
- { deltaId: log-level-waf-forward, fold, spec-id: core_plugin_middleware_log-level, confidence: high, candidates: [core_plugin_middleware_log-level] }
- { deltaId: sidecar-5xx-drain, fold, spec-id: core_plugin_middleware_sidecar-response, confidence: high, candidates: [core_plugin_middleware_sidecar-response] }
