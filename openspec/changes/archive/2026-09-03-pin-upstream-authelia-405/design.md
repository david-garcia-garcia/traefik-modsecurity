## Context

See proposal.md Why. Runtime already copies sidecar 3xx/4xx and sets inbound Host (`pkg/modsecurity/serve.go`). Explore measured the starter test pass. Identity owners: inbound `Request.Host`; Traefik leftover `X-Forwarded-For` / `X-Real-Ip`. This change adds a unit pin only.

## Goals / Non-Goals

**Goals:**

- Land `pkg/modsecurity/upstream_issue_13_test.go` against `New` / `ForRoute` / `httptest` WAF (same seam as `serve_test.go`).
- Keep the starter form-urlencoded login body as a plugin fixture.

**Non-Goals:**

- Authelia compose, ForwardAuth labels, or a 405 config key.
- Changing Host/XFF/`denyVerbsWithBody` runtime.

## Decisions

- **httptest pin, not live Authelia.** Alternative: Pester + Authelia image. Rejected: caller forbade compose; Authelia is not in this tree.
- **Form body, not Authelia JSON.** Alternative: official `application/json` username/password. Rejected: explore assumed the starter fixture; Authelia is not the system under test.
- **Fold existing specs.** Alternative: new `core_plugin_middleware_authelia-405` leaf. Rejected: FindSpecHost small adjustment; no new Authelia domain.

## Risks / Trade-offs

- [Risk] Operators still see 405 if the sidecar or nginx `limit_except` returns it. → Mitigation: test documents copy-vs-invent; no product knob.
- [Risk] Form fixture drifts from Authelia JSON. → Mitigation: research packet states the official contract; test comment names the fixture.

## Migration Plan

None. Tests-only; no deploy change.

## Open Questions

None. Deferrable unknowns live on `devstate/explore.md`.
