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
  Decision: assumed — expect 200 and a whoami body (`Hostname`). traefik/whoami writes a generated text page and does not implement Range/206; a drain 416 would be a leftover sidecar copy, not app partial content. Implement will assert success (not 416) plus whoami markers (`Hostname` and/or `X-Waf-Status` allow). If measure shows 206, accept 200 or 206.
  By: explore

- Q: Does nginx dummy 416 on `Range: bytes=10240-`?
  Decision: assumed — assert 416 on `apache-whoami` only (`Test-IsWhoamiOrigin` and stack name `apache-whoami`). Skip `nginx-whoami` unless implement measures 416. Apache whoami is the documented dummy failure (`httpd-vhosts.drain.conf` comments; inspect-only design).
  By: explore

- Q: Does a 12–16 MiB POST to `/large-body-test` return 200 on drain, or CRS 413?
  Decision: assumed — assert not 5xx (AH01084 class). Do not require 200. Compose sets `MODSEC_REQ_BODY_LIMIT=10485760` (10 MiB) and `MODSEC_REQ_BODY_NOFILES_LIMIT=1048576` (1 MiB) in `docker-compose.test.yml` / `docker-compose.test.nginx.yml`. A 12–16 MiB `data=aaa…` body is over both; CRS Reject is 413 (`knowledge/research/ext_modsecurity_http-status_deny-vs-error`). 413 is not 5xx. Prefer 200 only if implement measures 200. Do not change compose limits.
  By: explore

- Q: Is apache-whoami 12–16 MiB POST stably 5xx (dummy AH01084)?
  Decision: assumed — skip whoami large-POST contrast unless implement measures a stable 5xx. CRS 413 likely happens before ProxyPass, so dummy 5xx may never appear at 12–16 MiB. Drain not-5xx is the pin. Do not flake `nginx-whoami`.
  By: explore

- Q: Who already owns client identity for these tests?
  Decision: resolved — Traefik `ClientHost` plus CRS `X-Real-IP` / `REMOTEIP_INT_PROXY` / nginx `real_ip` overlays. This ticket does not add or reconstruct identity.
  By: explore

- Q: Should we raise compose body limits so 12–16 MiB can be 200?
  Decision: assumed — no. Out of scope. Ticket is tests only. Not-5xx is the MUST.
  By: explore
