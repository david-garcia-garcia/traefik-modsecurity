# Specs
change: remove-dummy-crs-origin
- folded core_crs_sidecar_inspect-only
archive-verdict: { deltaId: core_crs_sidecar_inspect-only, fold, spec-id: core_crs_sidecar_inspect-only, confidence: high }
archived: openspec/changes/archive/2026-09-03-remove-dummy-crs-origin/

change: inspect-only-crs-sidecar (catalog cleanup)
- folded core_crs_sidecar_inspect-only
archive-verdict: { deltaId: core_crs_sidecar_inspect-only, fold, spec-id: core_crs_sidecar_inspect-only, confidence: high, candidates: [core_crs_sidecar_inspect-only, core_plugin_middleware_sidecar-request, core_plugin_middleware_sidecar-response] }
sync: skipped — catalog already current from remove-dummy-crs-origin (delta would regress whoami/four-stack requirements)
archived: openspec/changes/archive/2026-09-03-inspect-only-crs-sidecar/
