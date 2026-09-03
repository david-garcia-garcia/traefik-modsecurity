---
url: https://github.com/traefik/traefik/blob/65f9d0663202b0ebf7941da0c4af0f1953525ce6/pkg/plugins/middlewareyaegi.go
title: pkg/plugins/middlewareyaegi.go
fetched: 2026-09-03
authority: source
ref: github.com/traefik/traefik@65f9d0663202b0ebf7941da0c4af0f1953525ce6:pkg/plugins/middlewareyaegi.go
---

Tag v3.6.9. Import: `github.com/mitchellh/mapstructure`.

`createConfig(config map[string]any)`:

- Calls `CreateConfig()` with no arguments.
- Empty `config` → return that `*Config` with no decode.
- Otherwise:

```go
cfg := &mapstructure.DecoderConfig{
    DecodeHook:       mapstructure.StringToSliceHookFunc(","),
    WeaklyTypedInput: true,
    Result:           vConfig.Interface(),
}
```

`TagName` and `MatchName` are unset. Decode errors wrap as `failed to decode configuration`.

`newMiddleware` takes `config map[string]any` (already-parsed dynamic plugin block).

Same `DecoderConfig` fields appear on Traefik `master` `middlewareyaegi.go` (fetched 2026-09-03; still no `TagName`).
