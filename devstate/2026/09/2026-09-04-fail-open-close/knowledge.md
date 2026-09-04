# Knowledge
- 2026-09-04 — updated `knowledge/devdocs/core_plugin_middleware.md`: `error` is WAF communication only; leave the status header unset on inbound `Canceled` and on a non-413 inbound body-read 502.
- 2026-09-04 — updated `knowledge/devdocs/core_plugin_middleware.md`: public `failMode` (`open`|`close`, default `open`); invalid values fail Prepare.
- 2026-09-04 — updated `knowledge/devdocs/core_plugin_health.md`: already-unhealthy skip follows prepared `failMode`.
