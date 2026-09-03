# Specs
change: close-remaining-waf-test-gaps
verdicts:
  - { deltaId: go-yml-race, new, spec-id: build_ci_github_go-test, confidence: high, candidates: [build_ci_github_lint] }
  - { deltaId: remaining-reject-negative-tests, fold, spec-id: core_plugin_middleware_prepare-validation, confidence: high, candidates: [core_plugin_middleware_prepare-validation] }
  - { deltaId: concurrent-mixed-body-servehttp, fold, spec-id: core_plugin_middleware_body-pool, confidence: high, candidates: [core_plugin_middleware_body-pool] }
- added build_ci_github_go-test
- modified core_plugin_middleware_prepare-validation
- modified core_plugin_middleware_body-pool
