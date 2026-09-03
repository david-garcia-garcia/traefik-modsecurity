# Explore

## Concepts

Allow path (`pkg/modsecurity/serve.go`): sidecar status below 300 → `discardSidecarBody` → optional request-header `ok` → `next.ServeHTTP(rw, req)`. Sidecar headers are not copied onto `rw`. Block path (`forwardResponse`) is the opposite.

`core_plugin_middleware_sidecar-response` already says the client gets `next`'s response, not the sidecar body. It does not name CORS / custom backend headers or forbid sidecar header leak.

Existing allow tests (`pkg/modsecurity/serve_test.go` `allow 200`) assert status and body `"next"` only.

```
 client ──► Route.ServeHTTP ──► Plugin.ServeHTTP
                                      │
                         sidecar 200  │
                                      ▼
                         discard sidecar body
                                      │
                                      ▼
                              next.ServeHTTP(rw)
                                      │
                         next sets CORS + X-Backend
```

## Decisions

- Land the untracked starter as-is. `CreateConfig` / `New` / `NewLogger` / `ForRoute` / `Close` match origin/main. Measured PASS (see below).
- Do not change `ServeHTTP`. Neither upstream hypothesis (`MaxBytesReader`/`requestTooLarge`, sidecar `Body.Close` after `next`) fires in native Go on this path.
- Fold the header invariant into `core_plugin_middleware_sidecar-response` (small adjustment). Do not invent a new family.
- Yaegi / Traefik `ResponseWriter` wrapping stays out of scope.

## Open questions

- Q: Which spec leaf owns allow-path backend response-header preservation?
  Decision: assumed — fold into `core_plugin_middleware_sidecar-response`; add one requirement that `next` headers survive and sidecar headers do not overlay the client.
  By: explore

- Q: Should this run change `ServeHTTP` (unwrap `MaxBytesReader`, move sidecar Close, copy sidecar headers on allow)?
  Decision: assumed — no. Caller and measurement say tests only. Land `pkg/modsecurity/upstream_issue_29_test.go` unchanged unless APIs drift (they did not).
  By: explore

- Q: Can Traefik Yaegi wrapping still drop backend headers in production?
  Decision: assumed — unknown and out of scope. Do not add Yaegi or Compose cases. A later Yaegi report is a new ticket.
  By: explore

- Q: Who already owns client identity (address, user, tenant, Host, trust hop) for this change?
  Decision: assumed — none. This test does not set or reconstruct those fields. Sidecar Host copy is unchanged (`proxyReq.Host = req.Host`).
  By: explore

- Q: Does `knowledge/devdocs/core_plugin_middleware.md` need a usage sentence that allow keeps `next` headers?
  Decision: assumed — yes at propose/devdocsimpact; one sentence on the existing packet. No new usage file.
  By: explore

## Measured

```
go test -count=1 -timeout 60s -v -run TestPlugin_UpstreamIssue29 ./pkg/modsecurity
```

PASS (`ok … 0.799s`). Six subtests: real `ResponseWriter` and `Recorder` × GET / OPTIONS / POST. CORS + `X-Backend` survived. Sidecar `X-Waf` did not leak.

**not reproduced** as a product bug. Reproduced as missing durable coverage on DestBranch (starter is untracked).
