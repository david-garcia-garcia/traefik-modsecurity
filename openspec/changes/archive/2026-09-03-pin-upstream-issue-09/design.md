## Context

See proposal.md Why. `Prepare` already remaps `MaxBodySizeBytes == 0` to `CreateConfig` (8 MiB). `readInboundBody` already calls `http.MaxBytesReader` only when `maxBodySizeBytes > 0`. Research: `knowledge/research/ext_http_maxbytesreader/`.

## Goals / Non-Goals

**Goals:**
- Land tests that fail if Prepare stops remapping 0 or if a leftover handler 0 installs `MaxBytesReader`.
- Keep the existing cap numbers and 413 path for a real oversize body.

**Non-Goals:**
- Changing the 8 MiB default or adding an operator “unlimited” sentinel.
- README / docs drift (#20).
- Product code unless the starter cannot compile (measured: it compiles and passes).

## Decisions

- **Tests only, starter file as-is.** Alternative: rewrite helpers to match root `New(ctx, next, cfg, name)`. Rejected: package tests already use `New` + `ForRoute`.
- **New spec leaf `core_plugin_middleware_maxbodysize`.** Alternative: fold into `prepare-validation` (construction only) or `body-pool` (pool cap). Rejected: this is the request-path body cap and MaxBytesReader(0) pin.
- **Forced handler 0 stays a test-only leftover, not a public unlimited mode.** Alternative: document 0 as unlimited. Rejected: ticket says do not change product cap behavior; Prepare remaps operator 0 to 8 MiB.

## Risks / Trade-offs

- [Starter asserts unexported `plugin.maxBodySizeBytes`] → Mitigation: same-package tests; do not export the field.
- [CI race vs httptest WAF] → Mitigation: existing package pattern; run `go test -race` on the file.

## Migration Plan

None. Tests and spec only; no deploy step.

## Open Questions

None. Ticket questions live on `devstate/explore.md`.
