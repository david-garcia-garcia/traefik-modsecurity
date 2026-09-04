# Devdocs impact
change: inspect-websocket-handshake

## Units
- Middleware — subsystem — `pkg/modsecurity/serve.go` handshake inspect + status-header Del; spec `core_plugin_middleware_websocket-handshake` / `status-header` / `bypass-rules`
- Integration — subsystem — `scripts/TestHelpers.ps1` `Invoke-WebSocketEcho` multi-message; `scripts/integration-tests.Tests.ps1` two-frame echo + Upgrade+SQLi

## Findings
none.
