---
url: https://doc.traefik.io/traefik-hub/api-gateway/guides/plugin-development-guide
title: Plugin Development Guide
fetched: 2026-09-03
authority: official
---

Yaegi middleware sample Config uses `json` tags whose names appear as dynamic YAML keys:

```go
type Config struct {
    HeaderName  string `json:"headerName,omitempty"`
    HeaderValue string `json:"headerValue,omitempty"`
}
```

Kubernetes Middleware example:

```yaml
spec:
  plugin:
    myPlugin:
      headerName: "X-Custom-Header"
      headerValue: "plugin-works"
```

`testData` in `.traefik.yml` must be “key-value pairs matching your plugin's Config struct.” Nested example in the same page: `testData.Headers.X-Custom-Header`.

The guide does not describe mapstructure or `TagName`. It does not show a slice of objects. Runtime default is `yaegi`.
