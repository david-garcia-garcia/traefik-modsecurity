# Explore

Verdict: in progress

## Concepts

**DestBranch baseline (`origin/main` @ `645f4a25`):** `go.mod` has no `traefik-middleware-utilities` require. In-tree `pkg/reclaim/` owns `Table`, package-level `Open` / `Default` / `Reset` / `ResetWith`, and extensive table tests. Root `modsecurity.go` `bindPlugin` calls `reclaim.Open(ctx, pluginKey(...), logger, create)` and type-asserts `*modsecurity.Plugin`.

**Upstream reclaim (`github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim` @ **v1.0.3**):** Process-wide helpers are not exported. Callers hold `*Table` from `reclaim.New(reclaim.Config{Grace: …})` at plugin package scope. `Open` / `OpenTyped` require a `create` that returns `(any, Hooks, error)`. Lifecycle teardown uses `Hooks.Close` (and optional Sleep/Wake), not reflection on `Close()` of the stored value. Test-only process reset is `(*Table).Reset()`, not package `ResetWith`.

**Call sites to migrate (enumerated):**

| Unit | Role |
|------|------|
| `modsecurity.go` | Production `reclaim.Open` |
| `plugin_reuse_test.go` | Six `reclaim.ResetWith` + cleanup |
| `loglevel_test.go` | `reclaim.Reset` |
| `pkg/reclaim/*` | Implementation + tests — delete |

**Out of scope (requirement):** simpleredis, windowcounter, tokenbucket, backendbackoff, iplookup; behavior changes beyond reclaim wiring.

```
Traefik New(ctx,…) ──► bindPlugin
                           │
                           ▼
              reclaim table (one per process)
                           │
         key plugin:<name>:<hash> ──► *modsecurity.Plugin
                           │
              ctx done ──► grace ──► Close idle HTTP
```

After import, the table instance lives in `traefik_modsecurity` (Yaegi-visible root), not `pkg/reclaim`.

## Decisions

- Pin **`github.com/david-garcia-garcia/traefik-middleware-utilities v1.0.3`** and vendor per `knowledge/devdocs/build_go_modules.md`.
- **Not a drop-in import path swap.** Upstream API differs from local `pkg/reclaim`; implement will adapt `bindPlugin` to `OpenTyped[*modsecurity.Plugin]` (call expression in root package) and supply `Hooks.Close` that calls `Plugin.Close()`.
- Hold one `*reclaim.Table` at package scope in `modsecurity.go` (lazy init with `DefaultGrace`), matching upstream usage guidance — not a second in-tree reclaim fork.
- Delete `pkg/reclaim/` entirely once tests pass; do not re-vendor reclaim logic into this repo.
- Replace test `Reset` / `ResetWith` with a root-package test helper that calls `(*Table).Reset()` on the same table `bindPlugin` uses (name TBD in implement; no restore of `pkg/reclaim`).
- Log constants (`reclaim_put`, etc.) and grace default (10s) align with upstream; Pester reclaim integration should stay valid without fixture changes.

## Open questions

- Q: Which semver tag of `traefik-middleware-utilities` should `go.mod` pin?
  Rank: additive asked — new module require; Desired adds the dependency
  Decision: resolved — **v1.0.3** (latest tag; includes `OpenTyped` and grace fixes). Source: `knowledge/research/ext_traefik-middleware-utilities_reclaim/notes.md`.
  By: explore

- Q: Does upstream `reclaim` match local `Open(ctx, key, logger, create)` and test `Reset` / `ResetWith` without adapter code?
  Rank: additive asked — requirement Unknowns
  Decision: resolved — **no.** Missing package-level `Open`/`Default`/`Reset`/`ResetWith`; `Open`/`OpenTyped` need `Hooks`; constructor is `New(Config)` not `NewTable` in production API.
  By: explore

- Q: How should `bindPlugin` wire `modsecurity.Plugin` teardown on upstream reclaim?
  Rank: bounded asked — reshapes existing `bindPlugin`; Desired routes all reclaim through upstream; **1** production call site (`modsecurity.go`, searched repo for `reclaim.Open`)
  Decision: resolved — `OpenTyped[*modsecurity.Plugin]` in `bindPlugin`; create returns `Hooks{Close: Plugin.Close, EnforceCloseBeforeOpen: false}`.
  By: implement

- Q: How do `plugin_reuse_test.go` and `loglevel_test.go` reset reclaim without upstream `ResetWith`?
  Rank: bounded asked — **3** test files (`plugin_reuse_test.go`, `loglevel_test.go`, `failmode_test.go`), **8** former `Reset`/`ResetWith` sites
  Decision: resolved — `resetPluginReclaimForTest` in `reclaim_test.go` replaces the shared table and restores `DefaultGrace` on cleanup.
  By: implement

- Q: Should in-tree `pkg/reclaim/table_test.go` move or stay after delete?
  Rank: bounded asked — Desired deletes `pkg/reclaim/`; table tests only lived there
  Decision: resolved — deleted `pkg/reclaim/` with the apply.
  By: implement

- Q: After `go get`, must `vendor/` include the module (and its transitives)?
  Rank: additive asked — Affected lists `go.mod`/`go.sum`; `build_go_modules.md` requires vendor refresh for Yaegi/CI
  Decision: resolved — `go.mod` pins v1.0.3; `vendor/` lists only `…/reclaim` (yaegi is not a reclaim import, so it was not vendored).
  By: implement

- Q: Will Yaegi still construct the plugin if `bindPlugin` uses `OpenTyped[*modsecurity.Plugin]`?
  Rank: bounded asked — production Traefik path; **1** Yaegi entry constructor chain via `New` → `bindPlugin` in `modsecurity.go`
  Decision: resolved — yes. `OpenTyped` stays a call expression in `modsecurity.go`. CI Integration Tests (apache-drain, nginx-drain) succeeded on this head.
  By: pullrequest

- Q: Who already owns client identity (address, user, tenant, Host, trust hop) for this change?
  Rank: additive asked — no identity fields in reclaim key
  Decision: assumed — **none** for this ticket. Reclaim key stays `plugin:` + middleware name + prepared-config hash; no new trust-hop or Host reconstruction.
  By: explore

- Q: When should `knowledge/devdocs/core_plugin_reclaim.md` reflect the upstream import?
  Rank: additive asked — subsystem usage changes when `pkg/reclaim` is removed
  Decision: resolved — `core_plugin_reclaim.md` and `core_plugin_layout.md` now name the utilities import and vendor path.
  By: devdocsimpact

## Measured

**DestBranch gap (requirement “Current” vs `origin/main`):** **reproduced.**

- `git diff origin/main...HEAD` on product paths is empty; branch only adds `devstate/` for this IssueKey.
- `origin/main:go.mod` — no `traefik-middleware-utilities` require (only `testify` direct).
- `origin/main` tree includes `pkg/reclaim/` (`928d99e…`).
- Worktree matches that baseline for `go.mod`, `modsecurity.go`, and `pkg/reclaim/`.

**Baseline tests (pre-import, worktree @ `197279b9`):**

```
go test -count=1 -timeout 120s ./...
```

PASS — root, `pkg/health`, `pkg/modsecurity`, `pkg/reclaim`.

## Knowledge

- created `knowledge/research/ext_traefik-middleware-utilities_reclaim/`
- updated `knowledge/research/index.md`, `knowledge/research/index_ext_traefik-middleware-utilities.md`
- `devstate/2026/09/2026-09-16-import-middleware-utilities/knowledge.md`
