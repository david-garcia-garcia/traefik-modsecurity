# Explore

## Concepts

```
  client POST /api/firstfactor
           │  Host=auth.example.com
           │  X-Forwarded-For leftover, X-Real-Ip
           ▼
     ┌─────────────┐
     │ Plugin core │  inspect-and-maybe-block
     └─────┬───────┘
           │ sidecar request (same method/path/body, inbound Host, headers as-is)
           ▼
     ┌─────────────┐
     │ WAF sidecar │
     └─────┬───────┘
           │
     ┌─────┴──────────────────────┐
     │ allow (<300)               │ 405 / other 3xx-4xx
     ▼                            ▼
  restore body                 copy sidecar page
  next (Authelia)              next skipped
  client ≠ 405                 client 405 (copied, not invented)
```

Upstream #13 access-log 405 is either a sidecar block or a Traefik/Authelia chain mistake. This plugin's local statuses are 400 / 413 / 502 or a copy of sidecar 3xx/4xx. Authelia official first-factor is POST `/api/firstfactor` → 200 or 401 (`knowledge/research/ext_authelia_api_firstfactor/`).

Measured 2026-09-03 (`go test ./pkg/modsecurity/ -count=1 -timeout 60s -run "TestPlugin_SidecarRequestCopiesHostAndForwardingHeaders|TestPlugin_UpstreamIssue13_PostFirstFactorNeverEmits405"`): **pass**. Plugin-invented 405 on that POST: **not reproduced**. Starter file compiles against this tree's `New` / `ForRoute` / `NewLogger`.

## Decisions

- Land the starter as a unit test only. Do not add Authelia compose, ForwardAuth labels, or a 405 knob.
- Fold the pin into existing sidecar-response (4xx copy includes 405) and sidecar-request (Host / XFF / X-Real-Ip as-is). Do not invent a new Authelia middleware family.
- Keep the starter form-urlencoded body. It is a plugin fixture, not Authelia's JSON contract.
- Identity on the sidecar request: reuse Traefik's leftover `X-Forwarded-For` and `X-Real-Ip`; reuse inbound `req.Host`. Do not append `RemoteAddr`.

## Open questions

- Q: Who already owns inbound Host, leftover X-Forwarded-For, and X-Real-Ip on the sidecar request?
  Decision: assumed — Host owner is Go `Request.Host` (inbound). XFF / X-Real-Ip owner is Traefik's entrypoint forwarded-headers wrapper (copied as-is). This plugin does not reconstruct those facts from `RemoteAddr`.
  By: explore

- Q: Should the issue-13 fixture use Authelia's official JSON body instead of form-urlencoded?
  Decision: assumed — keep the starter form body. The test pins plugin status/header copy, not Authelia parsing.
  By: explore

- Q: New spec leaf vs fold into sidecar-response / sidecar-request?
  Decision: assumed — fold. Add a 405-copy scenario on sidecar-response and an Authelia-shaped POST scenario on sidecar-request. No new 4th part; no Authelia domain.
  By: propose

- Q: Does build_testing_go need a usage update for `upstream_issue_*_test.go`?
  Decision: assumed — yes, one Key files line at implement/devdocsimpact if the file lands. No new Language term.
  By: explore
