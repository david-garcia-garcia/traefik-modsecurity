---
url: https://github.com/mitchellh/mapstructure/blob/v1.5.0/mapstructure.go
title: mapstructure.go DecoderConfig
fetched: 2026-09-03
authority: source
ref: github.com/mitchellh/mapstructure@v1.5.0:mapstructure.go
---

`DecoderConfig.TagName`: “The tag name that mapstructure reads for field names. This defaults to `mapstructure`.”

`DecoderConfig.MatchName`: “Defaults to `strings.EqualFold`.”

`NewDecoder`: if `TagName == ""` set `"mapstructure"`; if `MatchName == nil` set `strings.EqualFold`.

`decodeStructFromMap`: `fieldName := field.Name`; if `field.Tag.Get(TagName)` (before comma) is non-empty, that replaces `fieldName`. Then exact map index, else iterate keys with `MatchName`. No `json` tag is read unless `TagName` is `"json"`.

`decodeSlice`: for each index, `d.decode(name+"[i]", element, sliceElem)`. Element type may be a struct; that recurses into `decodeStruct`.

Weakly typed: a non-slice source can be lifted to a one-element slice. `StringToSliceHookFunc` (used by Traefik, defined in the same module) splits strings on a separator for string slices; it does not parse YAML objects.
