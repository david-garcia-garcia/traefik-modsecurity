# Explore

## Concepts

```
  client PUT /webdav/folder/mydb.kdbx.tmp  228565 bytes
                 │
                 ▼
     denyVerbsWithBody?  ──yes──► local 400 (GET/HEAD/…; not PUT)
                 │ no
                 ▼
     maxBodySizeBytes 8 MiB  ──over──► local 413
                 │ under
                 ▼
     sidecar (httptest here)
                 │
        200 ──► next + restored body
        400 / 413 ──► copy as security block (not local 413, not deny-verb 400)
        (CRS-docker nofiles 128 KiB is sidecar policy, not a plugin field)
```

- **Denied-verb body**: method on `denyVerbsWithBody` plus a present body → local 400, no sidecar. PUT is not on the CreateConfig default list.
- **Plugin cap**: `maxBodySizeBytes` default 8 MiB. 228565 is under it. This is not `SecRequestBodyNoFilesLimit`.
- **Security block**: sidecar 3xx/4xx copied to the client; `next` is not called.
- **Sidecar nofiles**: CRS-docker `MODSEC_REQ_BODY_NOFILES_LIMIT=131072`. Non-multipart PUT counts as “no files.” This ticket does not shadow that knob.

## Decisions

- Land the untracked starter as-is. Measured: `go test ./pkg/modsecurity/ -count=1 -timeout 60s -run "TestCreateConfig_PutIsNotDeniedAndKeepassSizeFitsDefaultCap|TestPlugin_KeepassWebDAVPutIsForwardedAndSidecar4xxCopied"` → `ok`.
- Tests only. No `Config` field, no `ServeHTTP` change, no README or demo compose edit.
- Pin the plugin half only. Do not start CRS-docker. The 400/413 cases stub sidecar policy.
- Propose will fold new scenarios onto existing deny-verb and sidecar-response spec leaves (small adjustment), not invent a plugin nofiles knob.

## Open questions

- Q: Does the untracked starter compile against this `origin/main` (`New` / `NewLogger` / `ForRoute` / `Close`)?
  Decision: resolved — both named tests passed on this worktree (`ok` in 0.826s). No API adapt needed.
  By: explore

- Q: Who already owns incoming Host / client address for the sidecar request?
  Decision: assumed — `ServeHTTP` already sets `proxyReq.Host = req.Host` and copies Traefik headers as-is. These tests do not reconstruct Host, REMOTE_ADDR, or XFF. Reuse that owner; do not add a second Host calculation.
  By: explore

- Q: Should this ticket add a live CRS-docker nofiles 128 KiB integration test?
  Decision: assumed — no. Caller asked in-process coverage. Sidecar 400/413 is stubbed.
  By: explore

- Q: Should README / demo compose document `MODSEC_REQ_BODY_NOFILES_LIMIT` in this change?
  Decision: assumed — no. Caller marked docs P2 out of scope.
  By: explore

- Q: Fold KeePass PUT scenarios into existing spec leaves, or create a new leaf?
  Decision: assumed — fold. `core_plugin_middleware_deny-verbs-with-body` already requires methods not on the list to inspect and forward (POST only today). `core_plugin_middleware_sidecar-response` already requires 3xx/4xx copy. Adding PUT + 228565 + sidecar 400/413 is a small adjustment. Confirm with FindSpecHost at propose.
  By: explore

- Q: Should the tests also assert the 5 MiB pool cap path?
  Decision: assumed — no. Bound the ask to the starter file. 228565 is under both caps; extra pool assertions are out of scope.
  By: explore
