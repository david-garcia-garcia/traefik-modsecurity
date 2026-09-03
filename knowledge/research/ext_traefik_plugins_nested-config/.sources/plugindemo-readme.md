---
url: https://github.com/traefik/plugindemo/blob/master/readme.md
title: Developing a Traefik plugin
fetched: 2026-09-03
authority: official
---

Required exports: `type Config struct { ... }` (fields arbitrary), `CreateConfig() *Config`, `New(ctx, next, config *Config, name) (http.Handler, error)`.

Dynamic file YAML (nested object under the plugin name):

```yaml
middlewares:
  my-plugin:
    plugin:
      example:
        headers:
          Foo: Bar
```

`.traefik.yml` `testData` uses the same nested shape (`Headers: { Foo: Bar }`). Catalog executes the plugin with that data at startup.
