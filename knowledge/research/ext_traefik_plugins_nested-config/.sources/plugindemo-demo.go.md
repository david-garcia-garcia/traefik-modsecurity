---
url: https://github.com/traefik/plugindemo/blob/master/demo.go
title: plugindemo demo.go Config
fetched: 2026-09-03
authority: official
---

Named Traefik Plugin Catalog skeleton. Nested Config field:

```go
type Config struct {
    Headers map[string]string `json:"headers,omitempty"`
}
```

`CreateConfig` returns `&Config{Headers: make(map[string]string)}`. `New` rejects empty `Headers`.

This is a nested map on Config, not a slice of structs. Same `json` tag convention Traefik Hub’s guide uses on flat string fields.
