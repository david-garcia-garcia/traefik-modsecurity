---
url: https://github.com/traefik/traefik/blob/65f9d0663202b0ebf7941da0c4af0f1953525ce6/pkg/plugins/middlewareyaegi.go
title: pkg/plugins/middlewareyaegi.go
fetched: 2026-09-01
authority: source
ref: github.com/traefik/traefik@65f9d0663202b0ebf7941da0c4af0f1953525ce6:pkg/plugins/middlewareyaegi.go
---

Tag v3.6.9 (`65f9d0663202b0ebf7941da0c4af0f1953525ce6`). Inspected from a shallow temp clone of that tag; clone deleted after extract.

`newYaegiMiddlewareBuilder` evals `basePkg.New` and `basePkg.CreateConfig`.

`newHandler` calls `New` with four reflect values only:

1. `context.Context`
2. `http.Handler` (`next`)
3. the decoded `*Config` value
4. `middlewareName` (`string`)

No logger is passed.

`createConfig` calls `CreateConfig()` with no args, then `mapstructure` decode of the dynamic plugin map into that struct (`WeaklyTypedInput: true`, `StringToSliceHookFunc(",")`). DecoderConfig sets no `TagName` and no `MatchName`.

`newInterpreter` sets Yaegi `interp.Options`:

- `Stdout: logs.NoLevel(*log.Ctx(ctx), zerolog.DebugLevel)`
- `Stderr: logs.NoLevel(*log.Ctx(ctx), zerolog.ErrorLevel)`
