---
url: https://github.com/corazawaf/coraza/blob/5c9a34ab5b860479f18fa237bea7a05c6c3f9d93/http/websocket_test.go
title: Coraza WebSocket upgrade tests
fetched: 2026-09-03
authority: source
ref: corazawaf/coraza@5c9a34ab5b860479f18fa237bea7a05c6c3f9d93:http/websocket_test.go
---

wsUpgradeViaWriteHeader requires Sec-WebSocket-Key, writes 101 + Sec-WebSocket-Accept, then Hijack.

TestWebSocketUpgradeViaResponseWriter: full RFC handshake + masked text frame echo through WrapHandler.

TestWebSocketUpgradeBlockedByWAF: SecRule REQUEST_HEADERS:X-Attack deny phase 1. Same GET /ws handshake plus X-Attack: malicious. Expect 403 Forbidden, not 101.
