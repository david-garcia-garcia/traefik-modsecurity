## Why

Inspect-only CRS is already on `main` (this repo PR #31). Dummy-hop failures from [acouvreur/traefik-modsecurity-plugin#25](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/25) (Range → sidecar 416 copied as a WAF block) and [acouvreur/traefik-modsecurity-plugin#23](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/23) (large POST → Apache AH01084 / dummy 5xx) are not pinned by CI-visible Pester. The drain Range It only asserts not-416. The 16 MiB POST lives in `scripts/integration-tests.BodySize.Tests.ps1`, which `.github/workflows/integration-test.yml` does not run.

## What Changes

- Strengthen the drain Range It in `scripts/integration-tests.Tests.ps1`: not 416, plus a successful labeled-app response (whoami markers).
- Add an `apache-whoami` Range It that expects 416 so drain is the fix, not a plugin Range strip. Skip `nginx-whoami` unless that dummy also 416s.
- Add a drain `It` that POSTs ~12–16 MiB to `/large-body-test` and asserts not 5xx (60s timeout). Do not require 200 (compose CRS body limits are 10 MiB / 1 MiB). Skip whoami large-POST contrast unless a stable 5xx is measured.
- Wait for `/large-body-test` in the main suite `BeforeAll`.
- Keep the existing CRS POST-body probe It.
- Do not change `pkg/modsecurity/serve.go`, drain vhosts, compose `MODSEC_*`, or the integration workflow path.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_crs_sidecar_inspect-only`: CI-visible Pester MUST prove drain Range is a labeled-app success (not merely not-416), apache-whoami Range MAY still be sidecar 416, and drain large POST to `/large-body-test` MUST NOT be 5xx.

## Impact

- `scripts/integration-tests.Tests.ps1` (and `scripts/TestHelpers.ps1` only if a helper is required)
- `knowledge/devdocs/build_testing_integration.md` (usage of the Its)
- Four-stack CI matrix already runs the main file — no workflow change
- Plugin, drain overlays, and whoami stacks unchanged
