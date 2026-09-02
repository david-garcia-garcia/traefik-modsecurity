# Devdocs impact
change: close-remaining-waf-test-gaps

## Units
- Unit tests — subsystem — `knowledge/devdocs/build_testing_go.md`
- GitHub CI — subsystem — `knowledge/devdocs/build_ci_github.md`
- Body buffer pool — pattern — `knowledge/devdocs/core_plugin_middleware.md` (pool usage already documented)
- Prepare validation — pattern — `knowledge/devdocs/core_plugin_middleware.md`

## Findings
- [x] stale-usage  GitHub CI / Unit tests — `go.yml` Test is now `go test -race -v ./...`; `build.yml` stays without `-race`. Produced in implement on `build_ci_github.md` and `build_testing_go.md`.
