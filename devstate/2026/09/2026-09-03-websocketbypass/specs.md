# Specs
change: inspect-websocket-handshake
verdicts:
  - deltaId: websocket-skip-removed
    fold: rename
    spec-id: core_plugin_middleware_websocket-handshake
    confidence: high
    candidates: [core_plugin_middleware_websocket-skip]
    note: leaf named the skip this change deletes; legal 4th part is handshake
  - deltaId: status-header-strip
    fold: fold
    spec-id: core_plugin_middleware_status-header
    confidence: high
    candidates: [core_plugin_middleware_status-header]
  - deltaId: bypass-rules-no-ws-skip
    fold: fold
    spec-id: core_plugin_middleware_bypass-rules
    confidence: high
    candidates: [core_plugin_middleware_bypass-rules]
- added core_plugin_middleware_websocket-handshake
- modified core_plugin_middleware_status-header
- modified core_plugin_middleware_bypass-rules
- removed core_plugin_middleware_websocket-skip (replaced by handshake)
