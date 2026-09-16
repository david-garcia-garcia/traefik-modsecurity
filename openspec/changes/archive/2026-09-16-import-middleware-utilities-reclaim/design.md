## Context

See `proposal.md` (Why). Today `modsecurity.go` calls in-tree `pkg/reclaim.Open` with a `create func() (any, error)` and relies on reflection-style `Close()` on the stored value. Upstream reclaim at **v1.0.3** exposes `New(Config)`, `(*Table).Open` / `OpenTyped`, explicit `Hooks`, and test reset via `(*Table).Reset()` only. Requirements in `core_plugin_middleware_instance-reuse` stay unchanged.

## Goals / Non-Goals

**Goals:**

- Single shared `*reclaim.Table` in package `traefik_modsecurity`, lazy-init with upstream default grace (~10s).
- `bindPlugin` uses `OpenTyped[*modsecurity.Plugin]` as a direct call in the root package (Yaegi-safe).
- Teardown via `Hooks.Close` calling `(*modsecurity.Plugin).Close()`; `EnforceCloseBeforeOpen: false` to preserve today’s permissive unmap-then-close ordering.
- Pin module **v1.0.3**, run `go mod vendor`, delete `pkg/reclaim/`.
- Test helper on the same table replaces `reclaim.Reset` / `ResetWith` in `plugin_reuse_test.go` and `loglevel_test.go`.

**Non-Goals:**

- Other packages from `traefik-middleware-utilities` (simpleredis, windowcounter, tokenbucket, backendbackoff, iplookup).
- Changing reclaim key format, grace semantics, or WAF handler behavior beyond reclaim wiring.
- Porting `pkg/reclaim/table_test.go` into this repo.

## Decisions

1. **Dependency pin v1.0.3** — Latest tag with `OpenTyped` and grace fixes (explore + research notes). Alternative: pseudo-version on main; rejected for reproducible vendor.
2. **Package-scoped table, not a second fork** — `var pluginReclaim *reclaim.Table` (name TBD) initialized once with `reclaim.New(reclaim.Config{Grace: reclaim.DefaultGrace})`. Matches upstream guidance; avoids reintroducing process-wide helpers in-tree.
3. **`OpenTyped[*modsecurity.Plugin]` in `bindPlugin`** — `create` returns `(plugin, reclaim.Hooks{Close: func() { plugin.Close() }}, nil)`. Replaces local `Open(ctx, key, logger, create)` signature. Alternative: untyped `Open` + type assert only; rejected because typed API is clearer and documented upstream.
4. **Test reset helper** — Unexported or test-only function in root package: call `pluginReclaim.Reset()` and restore default grace in `t.Cleanup` (mirrors prior `ResetWith` behavior). Alternative: export upstream table in tests only via internal test file in root package.
5. **No spec delta** — Behavior matches `core_plugin_middleware_instance-reuse`; `skip_specs: true` on the change.

## Risks / Trade-offs

- **[Yaegi generic call]** Direct `OpenTyped[*modsecurity.Plugin]` in root must remain a plain call expression, not hidden behind a generic alias → Confirm with existing CI / plugin load path in implement.
- **[Vendor size]** Module pulls transitives (including yaegi) into `vendor/` even though reclaim runtime is stdlib-only → Accept per `build_go_modules.md`; no production import of unused upstream packages.
- **[Devdocs lag]** `core_plugin_reclaim.md` still describes `pkg/reclaim` until devdocsimpact → Track in implement.

## Migration Plan

1. Add require + vendor before code switch so builds stay green incrementally if needed.
2. Switch `modsecurity.go` and tests; delete `pkg/reclaim`.
3. Run `go test ./...`; run reclaim-related Pester coverage if present.
4. Rollback: revert commit(s); no data migration.

## Open Questions

(none — explore resolved semver, API gap, bindPlugin hooks, test reset, and vendor refresh)
