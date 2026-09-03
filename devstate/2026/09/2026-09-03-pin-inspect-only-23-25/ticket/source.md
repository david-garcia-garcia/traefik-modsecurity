# Pin inspect-only CRS with CI-visible tests for acouvreur#23 and #25

Purpose: **integration tests** that prove inspect-only CRS (PR #31) actually fixed the dummy-hop failures from:

- https://github.com/acouvreur/traefik-modsecurity-plugin/issues/25 — mid-file `Range` → Apache dummy **416**, plugin copies it as a WAF block, real app never runs.
- https://github.com/acouvreur/traefik-modsecurity-plugin/issues/23 — large POST → Apache `AH01084` / whoami dummy echo; drain must not 5xx.

Inspect-only is **already on main** for demo (`httpd-vhosts.drain.conf`) and for test overlays (`apache-drain` / `nginx-drain`). Do **not** re-implement inspect-only. Do **not** change `pkg/modsecurity/serve.go`. Tests only (Pester + helpers if needed).

## What exists (too weak)

- `scripts/integration-tests.Tests.ps1` already has:
  - dummy present/absent Its
  - `Should not copy a sidecar 416 for Range bytes=10240- on a small GET` — **skips whoami**, drain only asserts **not 416** (does not assert 200 + backend body)
- `scripts/integration-tests.BodySize.Tests.ps1` has 16 MiB POST to `/large-body-test` not-5xx, but **CI does not run that file**. `.github/workflows/integration-test.yml` only runs `./scripts/integration-tests.Tests.ps1` on the four-stack matrix (`apache-whoami`, `nginx-whoami`, `apache-drain`, `nginx-drain`).
- `/protected` has `maxBodySizeBytes=1024`. Large #23 POSTs MUST use `/large-body-test` (`maxBodySizeBytes=20971520`).
- Use helpers: `Test-IsDrainOrigin` / `Test-IsWhoamiOrigin`, `Invoke-SafeWebRequest`, `New-RequestBodyOfSizeBytes`. Read `scripts/TestHelpers.ps1` and `knowledge/devdocs/build_testing_integration.md`.

## Required coverage (CI-visible)

Put new/strengthened `It`s in `scripts/integration-tests.Tests.ps1` (or change the workflow if you also keep BodySize — prefer the main file so all four stacks run them).

### #25 Range

- Drain (`apache-drain`, `nginx-drain`): GET `/protected` with `Range: bytes=10240-` must **not** be 416; client must get a successful backend response (whoami 200, or 206 if the labeled app serves partial content — measure, do not invent). Body/headers should show the **labeled app**, not a WAF 416 page.
- Whoami Apache (`apache-whoami`): this is the dummy failure — expect **416** (or skip nginx-whoami if nginx dummy does not 416; measure). That contrast proves drain is the fix, not a plugin Range strip.

### #23 large body

- Drain: POST ~12–16 MiB to `/large-body-test` must **not** be 5xx (AH01084 class). Prefer **200** from next if CRS allows a benign body. Timeout generously (60s).
- Apache whoami: dummy hop often 5xx on that size — skip or assert 5xx **only if you measure it**; do not flake nginx-whoami. Drain is the pin that “inspect-only fixed it.”

Keep CRS POST-body probe still 403-class on drain (already an It). Do not skip that.

Fold specs onto existing integration / inspect-only leaves if they exist (`core_crs_sidecar_inspect-only` or testing specs). FindSpecHost before new spec folders.

## Delivery card

Every full card AND the final PR summary MUST short-reference both upstream issues:

[acouvreur/traefik-modsecurity-plugin#23](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/23)
[acouvreur/traefik-modsecurity-plugin#25](https://github.com/acouvreur/traefik-modsecurity-plugin/issues/25)

Also note this repo’s inspect-only PR #31 as the product fix these tests pin.
