# Requirement
IssueKey: 2026-09-03-pin-inspect-only-23-25

## Problem
Inspect-only CRS (this repo PR #31) is already on `main`. Dummy-hop failures from [acouvreur#25](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/25) (Range → sidecar 416 copied as WAF block) and [acouvreur#23](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/23) (large POST → Apache AH01084 / dummy 5xx) are not pinned by CI-visible Pester. The existing Range It only asserts not-416 on drain. The 16 MiB POST lives in `scripts/integration-tests.BodySize.Tests.ps1`, which CI does not run.

## Current (code)
- Drain Range It: `scripts/integration-tests.Tests.ps1` (`Should not copy a sidecar 416 for Range bytes=10240- on a small GET`) skips unless `Test-IsDrainOrigin`; asserts `$response.StatusCode | Should -Not -Be 416`. Does not assert success status or labeled-app body.
- Whoami Range contrast: `not found` — no It expects 416 on `apache-whoami`.
- 16 MiB POST not-5xx: `scripts/integration-tests.BodySize.Tests.ps1` (`Should handle 16MB request near 20MB limit without 5xx transport errors`) hits `/large-body-test` with `New-RequestBodyOfSizeBytes` and 60s timeout. Asserts status `< 500` only.
- CI path: `.github/workflows/integration-test.yml` sets `Run.Path` to `./scripts/integration-tests.Tests.ps1` only (four-stack matrix). BodySize file is not in that path.
- `/protected` cap: `docker-compose.test.yml` `waf-middleware` `maxBodySizeBytes=1024`. Large #23 POSTs on `/protected` would 413 before dummy/drain.
- `/large-body-test` cap: `docker-compose.test.yml` `whoami-large-body-test` `maxBodySizeBytes=20971520`. Same labels in `docker-compose.test.nginx.yml`.
- Helpers: `scripts/TestHelpers.ps1` — `Test-IsDrainOrigin`, `Test-IsWhoamiOrigin`, `Invoke-SafeWebRequest`, `New-RequestBodyOfSizeBytes`.
- CRS POST-body probe: `scripts/integration-tests.Tests.ps1` (`Should block a CRS SQL-injection probe in the POST body`) asserts status `>= 400` on `/protected`.
- Dummy present/absent: same file, `Get-DummyContainerName` + origin helpers.
- Inspect-only product: `crs-apache/httpd-vhosts.drain.conf`, `docker-compose.test.apache-drain.yml`, `docker-compose.test.nginx-drain.yml`. Plugin copy of sidecar 4xx: `pkg/modsecurity/serve.go` (do not change).
- Spec leaf (unarchived change, not in `openspec/specs/`): `openspec/changes/inspect-only-crs-sidecar/specs/core_crs_sidecar_inspect-only/spec.md` — Range drain SHALL NOT 416; whoami MAY 416. No large-POST / AH01084 scenario. No testing-family spec in `openspec/specs/`.

## Desired
- CI-visible `It`s in `scripts/integration-tests.Tests.ps1` (preferred) so all four stacks run them.
- Drain Range: GET `/protected` `Range: bytes=10240-` is not 416; client gets a successful backend response (measure 200 vs 206); body/headers show the labeled app, not a WAF 416 page.
- Apache whoami Range: expect 416 (measure; skip `nginx-whoami` if nginx dummy does not 416). Contrast proves drain is the fix, not a plugin Range strip.
- Drain large POST: ~12–16 MiB to `/large-body-test` is not 5xx; prefer 200 if CRS allows a benign body. Timeout 60s.
- Apache whoami large POST: skip or assert 5xx only if measured; do not flake `nginx-whoami`. Drain is the pin.
- Keep the existing CRS POST-body probe It (403-class on drain).
- Fold OpenSpec onto existing inspect-only / integration leaves after FindSpecHost. Tests only.

## Affected
- `scripts/integration-tests.Tests.ps1` (strengthen / add Its; wait for `/large-body-test` if that It is added)
- `scripts/TestHelpers.ps1` only if a new helper is required
- `.github/workflows/integration-test.yml` only if BodySize is kept as the #23 home instead of the main file
- `openspec/changes/<new>/` folding onto `core_crs_sidecar_inspect-only` or a testing leaf
- `knowledge/devdocs/build_testing_integration.md` if usage of the Its changes

## Out of scope
- Re-implement inspect-only CRS
- Any change to `pkg/modsecurity/serve.go` or plugin copy-4xx behavior
- Changing `/protected` `maxBodySizeBytes=1024`
- Dropping whoami stacks or dummy
- Skipping the CRS POST-body probe
- Running or rewriting BodySize as the sole #23 pin without CI

## Unknowns
- Exact client status from labeled whoami on drain Range (200 vs 206) — measure.
- Whether nginx dummy 416s on `Range: bytes=10240-` — measure; skip if not.
- Whether apache-whoami 16 MiB POST is stably 5xx — measure; skip if not.
- Whether CRS allows a 12–16 MiB benign `data=aaa…` POST as 200 on drain (image `MODSEC_REQ_BODY_*` vs compose overrides).

## Tensions
- Existing Range It was written as the inspect-only pin and is weaker than this ticket (not-416 only, no whoami contrast).
- Large-body not-5xx already exists but is invisible to CI; ticket prefers moving coverage into the main file over changing the workflow.
- `core_crs_sidecar_inspect-only` lives only under unarchived `openspec/changes/inspect-only-crs-sidecar/`, not `openspec/specs/`. FindSpecHost must decide fold vs new.
