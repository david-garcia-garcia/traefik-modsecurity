# Yaegi plugin nested Config

Traefik does not `json.Unmarshal` a plugin `Config`. Yaegi `CreateConfig()` allocates the struct; Traefik then **mapstructure-decodes** the dynamic plugin map into that value. Nested maps and slices of maps decode into nested structs and `[]struct` the same way a `[]string` field does. Official plugin docs show `json` tags and YAML keys that look like those names; Traefik’s decoder does **not** set `TagName: "json"`. Keys match the **Go field name** (case-insensitive) unless a `mapstructure` tag is present.

## Constructor and decode path

A Yaegi HTTP middleware must export `Config`, `CreateConfig() *Config`, and `New(ctx, next, config *Config, name)`. Dynamic YAML under `http.middlewares.<id>.plugin.<pluginName>` becomes `map[string]any` and is passed to `createConfig`.

Owner: official [plugindemo readme](https://github.com/traefik/plugindemo/blob/master/readme.md) and [Traefik Hub plugin development guide](https://doc.traefik.io/traefik-hub/api-gateway/guides/plugin-development-guide).

Traefik v3.6.9 (`65f9d0663202b0ebf7941da0c4af0f1953525ce6`) `createConfig`:

1. `CreateConfig()` (no args)
2. If the map is empty, return that pointer unchanged
3. Else `mapstructure.NewDecoder` with `WeaklyTypedInput: true`, `StringToSliceHookFunc(",")`, `Result: vConfig.Interface()`
4. **No `TagName`. No `MatchName`.**

Same decoder options on current `master` `pkg/plugins/middlewareyaegi.go` (fetched 2026-09-03).

Owner: `traefik/traefik@65f9d06:pkg/plugins/middlewareyaegi.go`.

Extracts: `.sources/middlewareyaegi.go.md`, `.sources/plugindemo-readme.md`, `.sources/plugin-development-guide.md`

## What mapstructure does with those options

`mitchellh/mapstructure` v1.5.0 (Traefik’s import): empty `TagName` becomes `"mapstructure"`; empty `MatchName` becomes `strings.EqualFold`.

For each exported field, the decoder reads tag `mapstructure`. If that tag is missing or empty, the **field name** is the key. It then finds a map key with `EqualFold`. A `json:"pathRegexp,omitempty"` tag is **ignored**.

`decodeSlice` walks each element and `decode`s it into the slice element type. `decodeStruct` walks nested maps the same way. A YAML sequence of mappings therefore fills `[]SomeStruct` when each mapping’s keys EqualFold the struct field names.

`StringToSliceHookFunc(",")` is for splitting a **string** into a string slice (`denyVerbsWithBody: "GET,HEAD"`). It is not a list-of-objects parser. A `[]struct` field needs a YAML sequence (or the equivalent nested map from labels/KV).

Owner: `mitchellh/mapstructure@v1.5.0:mapstructure.go` (`DecoderConfig`, `NewDecoder`, `decodeSlice`, `decodeStructFromMap`).

Extract: `.sources/mapstructure.go.md`

## Official nested example (map, not slice)

plugindemo `Config` is a nested object, not a slice:

```go
Headers map[string]string `json:"headers,omitempty"`
```

Dynamic YAML (plugindemo readme):

```yaml
plugin:
  example:
    headers:
      Foo: Bar
```

Hub guide uses flat `json` tags (`headerName`, `headerValue`) and matching YAML keys. Catalog `testData` uses the same shape as dynamic config (`Headers: { Foo: Bar }`).

Owner: [plugindemo demo.go](https://github.com/traefik/plugindemo/blob/master/demo.go) and the readme dynamic-config block.

Extracts: `.sources/plugindemo-demo.go.md`, `.sources/plugindemo-readme.md`

## `[]struct{ Method, PathRegexp }` vs `[]string`

Same decoder, same matching rules.

```go
type BypassRule struct {
    Method     string `json:"method,omitempty"`
    PathRegexp string `json:"pathRegexp,omitempty"`
}

BypassRules []BypassRule `json:"bypassRules,omitempty"`
```

YAML that fills it (inference from mapstructure + Traefik’s plugin map; same key style as plugindemo `headers`):

```yaml
bypassRules:
  - method: GET
    pathRegexp: ^/health
```

Why it works: `BypassRules` EqualFolds `bypassRules`; `Method` / `PathRegexp` EqualFold `method` / `pathRegexp`. The `json` tags are catalog/docs convention, not what Yaegi-decode reads.

It would **not** work if the Go field name diverged from the YAML key and there was no `mapstructure:"thatKey"` tag. Example: `RE string \`json:"pathRegexp"\`` would look for key `RE`, not `pathRegexp`.

`[]string` fields (`DenyVerbsWithBody`) match the same way (field name + EqualFold, plus the comma-string hook). A slice of structs is the nested-struct case of `decodeSlice`, not a special Traefik feature.
