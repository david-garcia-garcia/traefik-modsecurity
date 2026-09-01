# core / plugin

## Middleware
priority: normal
local: core_plugin_middleware.md
description: How Traefik loads this plugin and how an implementer extends CreateConfig, New, and ServeHTTP.

## Layout
priority: normal
local: core_plugin_layout.md
description: How this repo splits the root plugin package from pkg/ subpackages and supporting trees.

## Reclaim table
priority: normal
local: core_plugin_reclaim.md
description: Process table that reuses one plugin core per middleware name and config.

## Health tracker
priority: normal
local: core_plugin_health.md
description: Shared WAF failure backoff owned by one plugin core.
