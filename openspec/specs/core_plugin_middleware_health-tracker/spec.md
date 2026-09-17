# core_plugin_middleware_health-tracker

## Purpose

Defines how the plugin trips WAF fail-open after repeated sidecar failures inside a tumbling window, and which defaults apply when an operator enables backoff without setting threshold or window.

Requirements for that deleted tumbling-window counter moved to `core_plugin_middleware_waf-backoff`.
