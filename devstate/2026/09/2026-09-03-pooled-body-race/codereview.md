# Code review
change: pooled-body-alias-copy-out
pin: origin/main (6dae0ab)...HEAD (53789d3)
command: git diff origin/main...HEAD -- . ':!devstate' ':!.cursor'

## Standards
none.

Gotchas applied from `core_plugin_middleware.md`: copy pooled bytes then Put; do not return `buf.Bytes()` to ServeHTTP. Diff matches.

Commandments: copy-out lives in `readInboundBody` (Fix the cause, One job). `ownedBody` names the role. Test types say `test`. No extra Config.

## Spec
none.

Requirement `Pooled body bytes are not aliased after Put` — `pkg/modsecurity/body.go:60-63` copy then Put; `TestPlugin_PooledBodyNotAliasedAfterPut` covers the delayed 403 read. Allow-path body identity remains covered by existing body-pool tests. Tasks 1–3 checked.

## Security
none.

The diff removes a tenant-body alias (source: inbound POST; sink: later sidecar/`next` reader). No new secrets, egress, headers, or fail-open. Test payloads are `0xAA`/`0xBB` fills.

## Performance
none.

Copy is bounded by `maxBodySizeBytes` / pool cap (`MaxBytesReader` still wraps the inbound read). Extra alloc equals one body; not an unbounded map or uncapped ReadAll. Design chose copy-out over waiting.

## Applied
none (no hard findings).

## Recorded-and-skipped
none.
