# Specs

change: import-middleware-utilities-reclaim

## Spec ids

added: (none)

modified: (none)

skip_specs: true — observable behavior unchanged vs `core_plugin_middleware_instance-reuse`; implementation source only.

## FindSpecHost

Evaluated before spec writes (no delta folders created).

| delta topic | verdict | spec-id | confidence | candidates |
|-------------|---------|---------|------------|------------|
| Plugin instance reuse / reclaim wiring | fold (no requirement delta) | core_plugin_middleware_instance-reuse | high | core_plugin_middleware_instance-reuse |

Rationale: reclaim table ownership moves from `pkg/reclaim` to upstream `traefik-middleware-utilities/reclaim`; keys, grace, reuse, and dispose semantics stay as the existing leaf specifies. No new fourth-part leaf; no modified delta file.
