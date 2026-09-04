# Codereview
change: inspect-websocket-handshake
pinned: origin/main = 6dae0abb6788aee781abeec4593ad9557792498a
head: 2d048337864afb14f0ee34a048ec291eb5d97246
diff: git diff origin/main...HEAD -- . ':!devstate' ':!.cursor'

## Standards
1. [judgement] Duplicated Code — `modsecurity_test.go:136` and `pkg/modsecurity/upstream_issue_05_test.go:102` — Both cases drive a handshake-shaped GET with forged `X-Waf-Status: ok`, sidecar 403, expect `blocked` and no `next`; the table case and `TestPlugin_ServeHTTP_HandshakeHitsSidecar` differ only in harness and hit counters.
   → Keep one owner (extend the table case with sidecar/next counters if needed, or drop the upstream duplicate).

2. [judgement] One job, one owner — `pkg/modsecurity/upstream_issue_05_test.go:100` — `TestPlugin_ServeHTTP_HandshakeHitsSidecar` is general ServeHTTP handshake-inspection coverage, not an acouvreur/traefik-modsecurity-plugin#5 regression; the file now mixes issue-#5 panic regressions with unrelated middleware behavior.
   → Move the handshake sidecar test beside the other ServeHTTP cases (`modsecurity_test.go` or a `serve_*_test.go` owner).

**Gotcha compliance (no hard findings):** `isWebsocket` and its skip branch are removed; handshake GETs follow the ordinary sidecar path. `New` is unchanged (no network I/O). `discardSidecarBody` ordering is unchanged. Body pool selection is untouched. Status-header `Del` at `ServeHTTP` entry aligns with the pasted Gotcha.

**Commandment compliance (no hard findings):** Product delta is minimal (`serve.go` removes the skip, adds one block comment). Names (`HandshakeHitsSidecar`, `EmptyHeadersDoNotPanic`, `Invoke-WebSocketEcho` multi-message param) spell the job. Fix removes the special-case classifier instead of adding call-site workarounds. Docs/README/devdocs trails updated for the behavior change.

## Spec
Requirements walked (change `specs/**/spec.md`):

| Requirement | Verdict |
|---|---|
| **Opening handshake HTTP is inspected** (`core_plugin_middleware_websocket-handshake`) | `pkg/modsecurity/serve.go:19-29` removes `isWebsocket` early return; handshake GETs follow the ordinary sidecar path. Unit tests in `modsecurity_test.go` (403 block, mixed-case, allow→next) and `upstream_issue_05_test.go` (`TestPlugin_ServeHTTP_HandshakeHitsSidecar`). Integration in `scripts/integration-tests.Tests.ps1` (two-frame echo + SQLi 403 on `/protected`). |
| **Client-supplied status header is discarded** (`core_plugin_middleware_status-header` ADDED) | `pkg/modsecurity/serve.go:19-22` `Del` before bypass/inspect/next. Block path tested (`Overwrites forged status header on handshake block`, `TestPlugin_ServeHTTP_HandshakeHitsSidecar`). Allow and bypass paths covered by existing `Set` wiring after `Del`. |
| **Allow path writes ok** (`core_plugin_middleware_status-header` MODIFIED) | `pkg/modsecurity/serve.go:126-128` sets `ok` on sidecar allow; handshake case in `modsecurity_test.go` (`Allows handshake GET after sidecar 200`). |
| **Omitted bypassRules inspects every request** (`core_plugin_middleware_bypass-rules` MODIFIED) | WebSocket skip removed; handshake GETs reach sidecar when no bypass rule matches (same `serve.go` path + tests above). |
| **REMOVED: Handshake-only WAF skip** (`core_plugin_middleware_websocket-skip`) | `isWebsocket` function and call deleted; not referenced in product code. |
| **REMOVED: Handshake detection does not panic** | Migrated to `TestPlugin_UpstreamIssue05_EmptyHeadersDoNotPanic` (empty and nil header maps complete without panic). |

Tasks.md items map to the above hunks; checked boxes are evidenced in the diff. Explore-phase research under `knowledge/research/` supports `devstate/requirement.md` intent and is not product surface named by any SHALL.

Clean axis: `none`.

## Security
**Diff reviewed:** `origin/main...HEAD` (pinned `6dae0abb`), commits through `2d04833`. Code touchpoints: `pkg/modsecurity/serve.go`, tests, docs/research, integration helpers.

**Walk (sources → sinks):**

| Change | New/changed source | Sink | Reachability |
|--------|-------------------|------|--------------|
| Remove `isWebsocket` skip | Client `Upgrade`/`Connection` on GET | ModSecurity sidecar via existing `httpClient.Do` | Same headers already forwarded on every inspected GET; only removes an unconditional bypass. Closes prior fail-open path (handshake never reached sidecar). |
| `Header.Del(modSecurityStatusRequestHeader)` at `ServeHTTP` start | Client-supplied status header | Request header forwarded to sidecar/`next` | Del runs before bypass, unhealthy, sidecar, and `next`; plugin `Set` writes authoritative token. Closes prior spoofing on websocket-skip path where client `ok` survived. |

**Checklist (all rows matched):**

- **Secrets in the tree / logs / examples** — No tokens, keys, or credential URLs added in code, tests, or fixtures. Research notes are public vendor excerpts only.
- **Client-controlled trust** — Diff removes trust (Del + end of websocket skip), does not add new trust of client headers for identity or allow/block.
- **Competing identity** — No new client-IP, Host, or tenant derivation.
- **Path or URL from config** — No new filesystem or config-path reads/writes.
- **New network egress** — No new outbound hosts; sidecar URL unchanged.
- **Sensitive headers** — Status header still carries decision tokens (`ok`, `blocked`, …), not secrets; client can no longer inject them.
- **Fail-open on deny** — No new allow-on-error paths. Removing websocket skip is fail-closed relative to WAF inspection.
- **Injection into a sink** — No shell, SQL, template, or formatted exec introduced.
- **Download integrity** — No runtime fetch/extract changes.
- **Error leak to the client** — No change to client-facing error bodies or headers.
- **New dependency** — No new Go modules.

**Residual (pre-existing, not introduced):** WebSocket frames after backend 101 remain outside this middleware (Traefik tunnel). Documented non-goal; not a new reachable sink in this diff.

Clean axis: `none`.

## Performance
**Diff reviewed:** `git diff origin/main...HEAD -- . ":!devstate" ":!.cursor"`  
**Commits:** `5543c9a fix: inspect WebSocket handshake GET instead of skipping WAF` (runtime change) plus docs, research, tests, and OpenSpec artifacts.

**Walk summary**

1. **New I/O:** WebSocket handshake GETs no longer skip `ServeHTTP`; they take the same sidecar path as other requests — `readInboundBody` → `httpClient.Do` → `discardSidecarBody`. Handshake GETs typically have an empty body, so body read is minimal. One bounded sidecar round-trip per new WebSocket connection; frames after 101 never re-enter this middleware.
2. **New collections:** None.
3. **Removed hot-path work:** `isWebsocket` and its header token scan are deleted.
4. **Added hot-path work:** `req.Header.Del(p.modSecurityStatusRequestHeader)` at the top of `ServeHTTP` — O(1) when configured.
5. **Existing bounds still apply:** `httpClient` timeout (`TimeoutMillis`, default 2000 ms), `readInboundBody` via `http.MaxBytesReader` when `maxBodySizeBytes > 0`, sidecar body drain capped at `sidecarBodyDrainLimit` (256 KiB). Test-only changes (`Invoke-WebSocketEcho` looping over a fixed `Message` array) are not production paths.

**Checklist (all rows checked)**

| Check | Result |
|-------|--------|
| Unbounded result set | N/A — no queries |
| I/O in a loop | N/A — no production loop over a growing set |
| Missing index on new query | N/A — no schema in diff |
| Unbounded collection or cache | N/A — no new accumulators |
| Unbounded payload or download | No — existing byte caps unchanged; handshake body usually empty |
| Missing deadline on outbound I/O | No — reuses shared `httpClient` with configured timeout |
| Unbounded concurrency | N/A — no new goroutines or fan-out |
| Quadratic work on growing set | N/A |
| Hot-path full scan or compile | No miss — removed `isWebsocket` scan; added work is one bounded sidecar call per handshake, not per frame |
| OFFSET pagination | N/A |
| Over-fetch | N/A |

**Clean axis:** `none`

## Applied
none.

## Recorded and skipped
- Standards 1: judgement — duplicated handshake-block tests; unattended applies hard findings only
- Standards 2: judgement — HandshakeHitsSidecar lives in upstream_issue_05_test.go; unattended applies hard findings only

Standards: 2 findings, worst: judgement Duplicated Code at `modsecurity_test.go:136`
Spec: none
Security: none
Performance: none
