## Context

See proposal.md for motivation. CreateConfig already omits PUT from `denyVerbsWithBody` and defaults `maxBodySizeBytes` to 8 MiB. `ServeHTTP` already copies sidecar 3xx/4xx. The gap is a test (and spec scenario) that uses the reporter’s verb, size, and 400/413 pair. Starter file `pkg/modsecurity/upstream_issue_14_test.go` already matches `New` / `NewLogger` / `ForRoute` / `Close` on this tree.

## Goals / Non-Goals

**Goals:**

- Land the starter tests without production edits.
- Keep sidecar nofiles policy in the sidecar (stub 400/413).

**Non-Goals:**

- A plugin field that shadows `SecRequestBodyNoFilesLimit`.
- README or demo compose `MODSEC_REQ_BODY_NOFILES_LIMIT`.
- Live CRS-docker in this change.
- Extra pool-cap assertions beyond the starter.

## Decisions

- **In-process httptest sidecar, not CRS-docker.** Alternatives: Pester/integration against owasp/modsecurity-crs. Rejected: caller asked plugin-half coverage; 128 KiB nofiles is sidecar config.
- **Land the starter as-is.** Alternatives: rewrite as table in `modsecurity_test.go`. Rejected: consume the existing file; APIs already match.
- **No plugin nofiles knob.** Alternatives: add `maxNoFilesBodyBytes`. Rejected: would lie about who rejects the body; owner of #14 said configure the OWASP container.
- **Fold spec deltas** onto `core_plugin_middleware_deny-verbs-with-body` and `core_plugin_middleware_sidecar-response`. Alternatives: new leaf `core_plugin_middleware_keepass-put`. Rejected: small adjustment to existing leaves; change kebab is not a legal 4th part.

## Risks / Trade-offs

- [Tests do not prove live CRS 128 KiB deny] → Mitigation: out of scope; stub 400/413. Operator docs remain a follow-up.
- [228565-byte payload per subtest] → Mitigation: one-shot `bytes.Repeat`; already passed in 0.826s.

## Migration Plan

None. Tests only. Rollback is revert the test file and spec deltas.

## Open Questions

None. Ticket-level choices live on `devstate/explore.md`.
