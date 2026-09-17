# Specs
change: adopt-upstream-backendbackoff

verdicts:
  - { deltaId: waf-backoff-owner, fold|new: new, spec-id: core_plugin_middleware_waf-backoff, confidence: high, candidates: [core_plugin_middleware_health-tracker] }
  - { deltaId: health-tracker-remove, fold|new: fold, spec-id: core_plugin_middleware_health-tracker, confidence: high, candidates: [core_plugin_middleware_health-tracker] }
  - { deltaId: health-failures, fold|new: fold, spec-id: core_plugin_middleware_health-failures, confidence: high, candidates: [core_plugin_middleware_health-failures] }
  - { deltaId: prepare-validation, fold|new: fold, spec-id: core_plugin_middleware_prepare-validation, confidence: high, candidates: [core_plugin_middleware_prepare-validation] }
  - { deltaId: instance-reuse, fold|new: fold, spec-id: core_plugin_middleware_instance-reuse, confidence: high, candidates: [core_plugin_middleware_instance-reuse] }

- added core_plugin_middleware_waf-backoff
- modified core_plugin_middleware_health-tracker
- modified core_plugin_middleware_health-failures
- modified core_plugin_middleware_prepare-validation
- modified core_plugin_middleware_instance-reuse
