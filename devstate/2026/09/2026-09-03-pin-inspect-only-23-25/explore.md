# Explore

## Concepts

```
  client
    │  GET Range: bytes=10240-     POST 12–16 MiB
    ▼
  Traefik plugin (unchanged)
    │  copy to sidecar
    ▼
  CRS sidecar
    ├─ whoami stack: ProxyPass / proxy_pass → dummy whoami
    │     tiny dummy body + Range → sidecar 416 → plugin copies block
    │     large POST → Apache AH01084 / dummy 5xx → plugin WAF failure
    └─ drain stack: inspect-only 200 (Apache unset Range; nginx max_ranges 0)
          sidecar < 300 → next → labeled whoami
```

- **Security block**: sidecar 3xx/4xx copied to the client; `next` is not called (`knowledge/devdocs/core_plugin_middleware.md`, `pkg/modsecurity/serve.go` `StatusCode >= 300 && < 500`).
- **WAF failure**: sidecar 5xx or transport error (`serve.go` `>= 500`).
- **Drain origin**: inspect-only 200, no dummy (`Test-IsDrainOrigin`).
- **Whoami origin**: unlabeled dummy is CRS `BACKEND` (`Test-IsWhoamiOrigin`).
- Product fix is already on `main` (PR #31). This ticket pins it with CI-visible Pester.

## Decisions

- Put new/strengthened Its in `scripts/integration-tests.Tests.ps1` so the four-stack CI matrix runs them. Do not change `.github/workflows/integration-test.yml`. Do not rely on `integration-tests.BodySize.Tests.ps1` for the #23 pin.
- Do not change `pkg/modsecurity/serve.go`, drain vhosts, or compose `MODSEC_*` / `maxBodySizeBytes`.
- Fold specs onto `core_crs_sidecar_inspect-only` (exists under unarchived `openspec/changes/inspect-only-crs-sidecar/`, not yet in `openspec/specs/`). FindSpecHost at propose. No new testing-family folder unless the librarian says `new`.
- Add `/large-body-test` to the main suite `Wait-ForAllServices` list when the large-POST It is added.
- Identity: this change does not set or reconstruct client IP, Host, or trust hop. Reuse Traefik `ClientHost` + existing `X-Real-IP` overlays. Existing audit Its stay.

## Open questions

- Q: What HTTP status does labeled whoami return on drain GET `/protected` with `Range: bytes=10240-`?
  Decision: resolved — apache-drain Pester passed 200 (or 206) plus `Hostname` in the body. `./Test-Integration.ps1 -Stack apache-drain` filtered Legitimate Request Handling.
  By: implement

- Q: Does nginx dummy 416 on `Range: bytes=10240-`?
  Decision: assumed — still skip `nginx-whoami` (not measured this run). `apache-whoami` Range 416 is resolved (Pester passed).
  By: implement

- Q: Does a 12–16 MiB POST to `/large-body-test` return 200 on drain, or CRS 413?
  Decision: resolved — apache-drain 16 MiB POST was not 5xx (It passed in 73ms; exact 200 vs 413 not printed). Assertion stays not-5xx.
  By: implement

- Q: Is apache-whoami 12–16 MiB POST stably 5xx (dummy AH01084)?
  Decision: resolved — skip remains. Not measured; drain not-5xx is the pin.
  By: implement

- Q: Who already owns client identity for these tests?
  Decision: resolved — Traefik `ClientHost` plus CRS `X-Real-IP` / `REMOTEIP_INT_PROXY` / nginx `real_ip` overlays. This ticket does not add or reconstruct identity.
  By: explore

- Q: Should we raise compose body limits so 12–16 MiB can be 200?
  Decision: assumed — no. Out of scope. Ticket is tests only. Not-5xx is the MUST.
  By: explore
