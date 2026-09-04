## REMOVED Requirements

### Requirement: Handshake-only WAF skip

**Reason:** A skip based on `Upgrade` / `Connection` is client-controlled and bypasses GET inspection. Other WAFs inspect the opening HTTP request and do not inspect frames after 101. This plugin already never sees those frames.

**Migration:** The opening handshake GET is inspected (`core_plugin_middleware_websocket-handshake`). Operators who need a skip for a WebSocket path that CRS false-positives use `bypassRules` or a Traefik router without this middleware.

### Requirement: Handshake detection does not panic

**Reason:** The plugin no longer classifies a handshake in order to skip. Empty and nil header maps follow the ordinary inspect path.

**Migration:** Covered by `core_plugin_middleware_websocket-handshake` scenarios for empty and nil header maps.
