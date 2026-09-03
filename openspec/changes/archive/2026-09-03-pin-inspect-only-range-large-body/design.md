## Context

See proposal.md Why. Inspect-only overlays and plugin copy-4xx are already on `main` (PR #31). `scripts/integration-tests.Tests.ps1` is the only Pester path `.github/workflows/integration-test.yml` runs on `apache-whoami`, `nginx-whoami`, `apache-drain`, and `nginx-drain`. Helpers: `Test-IsDrainOrigin`, `Test-IsWhoamiOrigin`, `Invoke-SafeWebRequest`, `New-RequestBodyOfSizeBytes` in `scripts/TestHelpers.ps1`. `/protected` is `maxBodySizeBytes=1024`; `/large-body-test` is `20971520`. Compose CRS limits are `MODSEC_REQ_BODY_LIMIT=10485760` and `MODSEC_REQ_BODY_NOFILES_LIMIT=1048576`.

## Goals / Non-Goals

**Goals:**

- CI-visible Pester pins for drain Range success + labeled-app markers, apache-whoami Range 416, and drain large POST not-5xx
- Keep the CRS POST-body deny It

**Non-Goals:**

- Plugin, drain vhost, or compose `MODSEC_*` / `maxBodySizeBytes` changes
- Changing the workflow to run `integration-tests.BodySize.Tests.ps1`
- Asserting 200 on 12–16 MiB POST, or asserting dummy 5xx without a measure

## Decisions

1. **Strengthen Its in the main file, not the workflow.** Alternative: add BodySize to CI. Rejected — four stacks already run the main file; one home for the pins.

2. **Drain Range asserts success + whoami markers, not only not-416.** Use `Hostname` in the body (existing `/protected` allow Its). Accept 200 or 206. Alternative: status-only. Rejected — a WAF error page that is not 416 would pass.

3. **Apache-whoami Range expects 416; skip nginx-whoami.** Alternative: assert 416 on both whoami stacks. Rejected until nginx dummy is measured. `INTEGRATION_STACK -eq 'apache-whoami'` plus `Test-IsWhoamiOrigin`.

4. **Large POST: 16 MiB to `/large-body-test`, 60s, not 5xx on drain.** Use `New-RequestBodyOfSizeBytes`. Do not require 200 (CRS 10 MiB / 1 MiB limits). Skip whoami contrast. Alternative: raise compose limits or use multipart under 10 MiB to force 200. Rejected — tests only.

5. **Wait for `/large-body-test` in `BeforeAll`.** Alternative: hit it cold. Rejected — other routes are already in `Wait-ForAllServices`.

6. **Identity stays with Traefik + CRS overlays.** No new client-IP reconstruction. Existing audit It unchanged.

## Risks / Trade-offs

- [16 MiB POST is 413 on every stack] → Mitigation: assert not 5xx; that is still the AH01084-class pin. 413 is documented CRS Reject.
- [Labeled whoami 416s on drain] → Mitigation: whoami writes a generated page and does not implement Range; if measure shows 416 with a whoami body, treat as app 416 and fail only when the body is a WAF page.
- [nginx-whoami 416 flakes] → Mitigation: skip that stack.
- [16 MiB string allocation in Pester] → Mitigation: existing BodySize It already does this; 60s timeout.

## Migration Plan

None. Tests only. Rollback: revert the Pester Its.

## Open Questions

None that change specs. Runtime 200 vs 413 and nginx 416 stay on `devstate/explore.md`.
