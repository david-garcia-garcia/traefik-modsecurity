# Explore

## Concepts

Upstream 1.2.0 wired `http.MaxBytesReader` with a leftover limit of `0`. Go treats that as “no bytes allowed”: the first byte of a login POST is `*http.MaxBytesError` and this plugin maps that to 413. This tree already remaps omitted and explicit `0` to 8 MiB in `Prepare`, and `readInboundBody` only wraps when `maxBodySizeBytes > 0`. The ticket is a regression pin, not a product change.

```
omitted / 0 ──Prepare──► 8 MiB ──New──► Plugin.maxBodySizeBytes
                                              │
leftover field 0 (test-only) ─────────────────┘
                                              │
                         > 0 → MaxBytesReader(limit)
                         = 0 → skip wrapper (no 413)
```

Starter `pkg/modsecurity/upstream_issue_09_test.go` compiles and passes on this tree (`go test ./pkg/modsecurity/ -run TestUpstreamIssue09`, 2026-09-03). No API adapt needed (`New` + `ForRoute` + `NewLogger` match).

Identity (client address, user, tenant, Host, trust hop): this pin does not set or reconstruct those facts. Tests use `httptest.NewRequest`. No owner to reuse.

## Decisions

- Land the starter file as-is. Tests only. Do not change `Prepare`, `readInboundBody`, or CreateConfig defaults.
- OpenSpec change name: `pin-upstream-issue-09`.
- Spec: new leaf `core_plugin_middleware_maxbodysize` (inbound body cap + MaxBytesReader wiring). Do not fold the ServeHTTP 413 pin into `prepare-validation` (that leaf is construction). Do not fold into `body-pool` (pool cap, not request cap).
- `prepare-validation` already says zero keeps the CreateConfig default. Do not duplicate a remap scenario there.
- Usage packet `core_plugin_middleware.md` does not say “wrap only when `maxBodySizeBytes > 0`”. Add that sentence in implement or devdocsimpact; do not invent Language.

## Open questions

- Q: Which spec leaf owns the #9 pin (Prepare 8 MiB + leftover-0 skip + login POST 200)?
  Decision: assumed — new `core_plugin_middleware_maxbodysize`; do not fold into `prepare-validation` or `body-pool`.
  By: explore

- Q: Should `NewLogger` be called on unprepared cfg (starter order)?
  Decision: assumed — keep starter; `New` calls `Prepare`; measured pass 2026-09-03.
  By: explore

- Q: Who already owns client address / user / tenant / Host / trust hop for this pin?
  Decision: assumed — none; this work does not reconstruct identity; tests use httptest Host only.
  By: explore

- Q: Does `core_plugin_middleware.md` need a MaxBytesReader skip sentence this run?
  Decision: assumed — yes, one usage sentence when implement or devdocsimpact runs; no Language write.
  By: explore
