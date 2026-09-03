# Explore

## Concepts

```
  large non-file POST (6 MiB form text)
              │
              ▼
     readInboundBody (MaxBytesReader)
              │
     ┌────────┴────────┐
     │ over plugin cap │  *http.MaxBytesError
     ▼                 │
   413 blocked         │  no sidecar
   next not called     │
                       ▼
              sidecar Do
                       │
            ┌──────────┼──────────┐
            ▼          ▼          ▼
         2xx allow   3xx/4xx    5xx
            next     copy block  WAF failure
                     (413 ok)    502 error
                                 (never copy 500)
```

- **Security block**: sidecar 3xx/4xx copied to the client (`knowledge/devdocs/core_plugin_middleware.md`). Sidecar 413 from `SecRequestBodyNoFilesLimit` is this class.
- **WAF failure**: sidecar 5xx or transport. Client 502 when backoff is 0. Not a copied 500.
- **Large non-file body**: reporter fixture (~8 MiB text form). Plugin does not split file vs text; the engine `SecRequestBodyNoFilesLimit` does.
- **Pin, not fix**: measured `go test ./pkg/modsecurity/ -run TestPlugin_UpstreamIssue11_LargeNonFileBodyNeverReturns500` → **ok** (0.878s) on this tree with the untracked starter. The bug is not present. Work is to commit that table.

## Decisions

- Land `pkg/modsecurity/upstream_issue_11_test.go` as-is. `New` / `NewLogger` / `ForRoute` / `CreateConfig` match origin/main. No production code.
- Fold any spec delta onto existing `core_plugin_middleware_waf-status` (already owns 413 block, 500-not-blocked, 502). Do not add a fifth underscore part or a new family.
- Change kebab: `pin-upstream-issue-11`.
- Do not raise `timeoutMillis` in the starter (in-process httptest finished in under 1s at default 2000 ms).
- Do not add a multipart-file contrast case. Ticket: file vs non-file is not a plugin distinction.

## Open questions

- Q: New spec leaf or fold onto an existing waf-status / sidecar-response spec?
  Decision: assumed — fold one pin scenario onto `core_plugin_middleware_waf-status`; do not create a new leaf.
  By: explore

- Q: Does the 6 MiB fixture need a higher `timeoutMillis` in unit tests?
  Decision: assumed — no; measured pass at CreateConfig default (2000 ms) in 0.878s.
  By: explore

- Q: Should propose also add a sidecar-response delta for “do not copy 5xx”?
  Decision: assumed — no; that requirement already lives on `core_plugin_middleware_sidecar-response` and `core_plugin_middleware_waf-status`. One fold on waf-status is enough.
  By: explore
