## Context

See proposal.md — Why. Mapping already lives in `pkg/modsecurity/serve.go` (`replyInboundBodyReadFailure`, 3xx/4xx `forwardResponse`, 5xx `recordWafFailureAndReplyToClient`). File vs non-file is not a plugin branch (`pkg/modsecurity/body.go`). Starter test `pkg/modsecurity/upstream_issue_11_test.go` already passes against origin/main APIs (`go test` 0.878s).

## Goals / Non-Goals

**Goals:**

- Commit one table-driven test that names upstream #11 and uses a large form POST.
- Keep the existing status mapping.

**Non-Goals:**

- Production code or mapping changes.
- A multipart-file contrast case.
- Sidecar `MODSEC_REQ_BODY_NOFILES_LIMIT` configuration.

## Decisions

- **Land the starter file as-is.** `New` / `NewLogger` / `ForRoute` / `CreateConfig` match this tree. Alternative: rewrite against older `modsecurity_test.go` helpers — rejected; the starter is already the pin.
- **6 MiB form body, pool cap 5 MiB.** Forces the ad-hoc `io.ReadAll` path the reporter’s ~8 MiB text body used. Alternative: tiny body — rejected; would not exercise the large-body class.
- **Keep default `timeoutMillis` (2000).** In-process httptest finished under 1s. Alternative: raise timeout “just in case” — rejected until a measured fail.
- **Fold spec onto `core_plugin_middleware_waf-status`.** FindSpecHost: fold, high confidence. Candidates: that leaf and `core_plugin_middleware_sidecar-response`. Alternative: new leaf — illegal extra concern; sidecar-response already says 5xx is not copied.

## Risks / Trade-offs

- [Risk] 6 MiB allocation per subtest could be slow on CI → Mitigation: three subtests, already 0.878s locally; CI Go test timeout is minutes.
- [Risk] Existing tests already cover the three mappings separately → Mitigation: this file is the named #11 pin, not a replacement.

## Migration Plan

None. Tests only. Rollback is revert the test and the spec delta.
