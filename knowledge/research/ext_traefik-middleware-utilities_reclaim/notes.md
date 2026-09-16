# traefik-middleware-utilities reclaim API

Pinned upstream: [david-garcia-garcia/traefik-middleware-utilities](https://github.com/david-garcia-garcia/traefik-middleware-utilities) at **v1.0.3** (`950b08de86b6fd9ea68ac1d205e17a379ec60522`). Local comparison target: worktree `pkg/reclaim/` (vendored copy before module import).

## Semver tags

`git tag -l` on the upstream repo lists **v1.0.0**, **v1.0.1**, **v1.0.2**, **v1.0.3** (no pre-releases). **v1.0.3** is the latest tag and adds `reclaim/opentyped.go` (`OpenTyped`); v1.0.0–v1.0.2 omit that file.

Owner: `github.com/david-garcia-garcia/traefik-middleware-utilities@950b08de:git tag -l` (clone 2026-09-16).

Extract: `.sources/tags-and-commits.md`

## go.mod

Module path: `github.com/david-garcia-garcia/traefik-middleware-utilities`. **Go 1.21**. Direct require: `github.com/traefik/yaegi v0.16.1` (used by repo tests and other packages; **not** imported from production `reclaim` sources).

Owner: `…/traefik-middleware-utilities@v1.0.3:go.mod`.

Extract: `.sources/go.mod.md`

## Package-level API: local vs upstream

| Symbol | Local `pkg/reclaim` | Upstream `reclaim` @ v1.0.3 |
|--------|---------------------|-----------------------------|
| `Open(ctx, key, logger, create)` | **Yes** — delegates to `Default().Open` | **No** — no `default.go`; callers use `(*Table).Open` |
| `Default()` | **Yes** — lazy process-wide `*Table` | **No** |
| `Reset()` | **Yes** — `ResetWith(DefaultGrace)` | **No** |
| `ResetWith(grace)` | **Yes** — replaces process table | **No** — only `(*Table).Reset()` on an instance |
| `NewTable(grace)` | **Yes** — production constructor | **Test helper only** — wraps `New(Config{Grace: grace})` in `table_test.go` |
| `New(cfg Config)` | **No** | **Yes** — production constructor |

Owner (upstream absence of package helpers): `…@v1.0.3:reclaim/` tree — no `default.go` at any tag v1.0.0–v1.0.3.

Owner (local presence): worktree `pkg/reclaim/default.go`, `pkg/reclaim/table.go` (`NewTable`).

Extracts: `.sources/default-local.md`, `.sources/table-open-reset.md`

## `(*Table).Open` signature and behavior

**Local:** `(t *Table) Open(ctx, key, logger, create func() (any, error)) (any, error)`. Disposal uses optional `Close()` on the stored value (`closer` interface). Grace orphan/reclaim state machine without Sleep/Wake hooks.

**Upstream:** `(t *Table) Open(ctx, key, logger, create func() (any, error), hooks Hooks) (any, error)` — fifth argument **required** at call sites (may be zero `Hooks{}`). Hooks carry `Sleep`, `Wake`, `Close`, and `EnforceCloseBeforeOpen`; stored at first successful create and **ignored** on later bind/reclaim for the same incarnation. Also exposes `OpenWithHooks` / `OpenTyped[T]`.

Owner: `…@v1.0.3:reclaim/table.go` (`Open`, `OpenWithHooks`, `Hooks`, `Reset`).

Local owner: worktree `pkg/reclaim/table.go` (`Open`, `NewTable`).

**API match for drop-in replace of local `pkg/reclaim`:** **no** — missing package-level `Open`/`Default`/`Reset`/`ResetWith`, different constructor (`New(Config)` vs `NewTable`), extra `Hooks` parameter, and different lifecycle (Sleep/Wake/Close hooks vs value `Close()`).

## Yaegi-safe imports in `reclaim` (production sources)

Non-test `.go` files in upstream `reclaim/` are **`table.go`** and **`opentyped.go`**. Imports are standard library only: `context`, `fmt`, `log/slog`, `sync`, `time`. No `unsafe`, no third-party modules in those files.

Repo tests copy non-`_test.go` reclaim sources into a GOPATH tree and evaluate with `interp.Use(stdlib.Symbols)` only (`yaegi_test.go` comment: “stdlib only (no unsafe)”).

Owner: `…@v1.0.3:reclaim/table.go`, `…@v1.0.3:reclaim/opentyped.go`, `…@v1.0.3:reclaim/yaegi_test.go` (`evalHookprobe`, `writeGopathReclaim`).

Extract: `.sources/yaegi-imports.md`

**Caveat (inference from upstream comments):** generics `OpenTyped[T]` must be invoked as a call expression in a package that names `T`; Yaegi v0.16.1 cannot resolve some cross-package generic instantiations (`opentyped.go`).

## Tag recommendation

Pin **`v1.0.3`** for reclaim: latest semver, includes `OpenTyped` and the AfterFunc grace-expire fix exercised by `TestYaegi_GraceExpireDoesNotHang`. Import path: `github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim`.

Implementers must **adapt** call sites (`modsecurity.go`, tests) to upstream API or add a thin local shim; upstream does not ship the process-wide helpers the worktree uses today.
