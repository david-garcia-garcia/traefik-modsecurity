# ext / traefik

## Yaegi plugin logging
priority: normal
local: ext_traefik_plugins_yaegi-logging/
description: How Traefik constructs a Yaegi HTTP middleware plugin and whether --log.level reaches it.

## Yaegi plugin nested Config
priority: normal
local: ext_traefik_plugins_nested-config/
description: How Traefik mapstructure-decodes nested structs and slices of objects from dynamic YAML into a Yaegi plugin Config.

## Proxy upgrade headers
priority: normal
local: ext_traefik_proxy_upgrade-headers/
description: How Traefik strips and restores hop-by-hop Upgrade and Connection before middleware and the backend.

## Proxy forwarded headers
priority: normal
local: ext_traefik_proxy_forwarded-headers/
description: Whether Traefik injects X-Forwarded-For and X-Real-IP before a Yaegi middleware sees the request.
