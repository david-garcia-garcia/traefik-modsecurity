# Yaegi plugin logging

Traefik does not pass its logger or `--log.level` into a Yaegi HTTP middleware plugin. `New` receives only `ctx`, `next`, `config`, and `name`. Plugin stdout that Yaegi captures is forced to Traefik DEBUG (stderr to ERROR) and then filtered by Traefik’s own log level.

## Constructor

A Yaegi middleware plugin must export `Config`, `CreateConfig() *Config`, and:

`func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error)`

Owner: official Traefik plugin demo ([plugindemo readme](https://github.com/traefik/plugindemo/blob/master/readme.md)). Same four arguments appear in Traefik Hub’s plugin guide. Traefik v3.6.9 calls that function with exactly those values — no logger.

Extracts: `.sources/plugindemo-readme.md`, `.sources/plugin-development-guide.md`, `.sources/middlewareyaegi.go.md`

## Traefik `--log.level`

`--log.level` / `log.level` is Traefik **install** (static) configuration. Official values: `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`, `PANIC`. Default `ERROR`. It is not a plugin `New` argument and is not documented as readable from plugin code.

Owner: [Traefik logs](https://doc.traefik.io/traefik/reference/install-configuration/observability/logs-and-accesslogs/).

Extract: `.sources/traefik-logs.md`

## How plugin writes reach Traefik

Official plugin docs: the only supported way to send logs to Traefik is `os.Stdout.WriteString` / `os.Stderr.WriteString`. There is no leveled plugin logger; docs say a level-based API is future work.

Owner: [plugindemo readme — Logs](https://github.com/traefik/plugindemo/blob/master/readme.md).

Traefik v3.6.9 (`65f9d0663202b0ebf7941da0c4af0f1953525ce6`) wires the Yaegi interpreter as:

- `Stdout` → `logs.NoLevel(*log.Ctx(ctx), zerolog.DebugLevel)`
- `Stderr` → `logs.NoLevel(*log.Ctx(ctx), zerolog.ErrorLevel)`

`NoLevel` hooks Traefik’s zerolog logger. If Traefik’s current min level is **above** the forced level, the hook **discards** the event. Captured plugin stdout is therefore hidden unless Traefik itself is at DEBUG (or TRACE). Captured stderr uses ERROR.

Owner: `traefik/traefik@65f9d06:pkg/plugins/middlewareyaegi.go` and `pkg/observability/logs/log.go`.

Extracts: `.sources/middlewareyaegi.go.md`, `.sources/log.go.md`

## Implication

A plugin cannot inherit Traefik’s log level. To gate its own lines, it must take a public Config field and filter before writing.
