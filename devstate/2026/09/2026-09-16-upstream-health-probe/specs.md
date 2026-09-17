# Specs
change: adopt-upstream-backendbackoff

verdicts:
  - { deltaId: waf-backoff, fold|new: new, spec-id: core_plugin_middleware_waf-backoff, confidence: high, candidates: [core_plugin_middleware_waf-backoff, core_plugin_middleware_health-tracker, core_plugin_middleware_health-failures, core_plugin_middleware_fail-closed, core_plugin_middleware_waf-status, core_plugin_middleware_instance-reuse] }
  - { deltaId: health-tracker-remove, fold|new: fold, spec-id: core_plugin_middleware_health-tracker, confidence: high, candidates: [core_plugin_middleware_health-tracker, core_plugin_middleware_waf-backoff, core_plugin_middleware_health-failures] }
  - { deltaId: health-failures, fold|new: fold, spec-id: core_plugin_middleware_health-failures, confidence: high, candidates: [core_plugin_middleware_health-failures, core_plugin_middleware_waf-backoff, core_plugin_middleware_health-tracker, core_plugin_middleware_waf-status] }
  - { deltaId: prepare-validation, fold|new: fold, spec-id: core_plugin_middleware_prepare-validation, confidence: high, candidates: [core_plugin_middleware_prepare-validation, core_plugin_middleware_waf-backoff, core_plugin_middleware_health-tracker] }
  - { deltaId: instance-reuse, fold|new: fold, spec-id: core_plugin_middleware_instance-reuse, confidence: high, candidates: [core_plugin_middleware_instance-reuse, core_plugin_middleware_waf-backoff, core_plugin_middleware_health-tracker] }

- added core_plugin_middleware_waf-backoff
- modified core_plugin_middleware_health-tracker
- modified core_plugin_middleware_health-failures
- modified core_plugin_middleware_prepare-validation
- modified core_plugin_middleware_instance-reuse
