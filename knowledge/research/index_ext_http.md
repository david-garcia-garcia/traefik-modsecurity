# ext / http

## WebSocket handshake
priority: normal
local: ext_http_websocket_handshake/
description: RFC 6455 opening handshake and RFC 9110 Connection/Upgrade token lists.

## HTTP/1 client body reuse
priority: normal
local: ext_http_client_body-reuse/
description: When Go's HTTP client can keep an HTTP/1 connection after Close.

## Request.ContentLength
priority: normal
local: ext_http_request_content-length/
description: How Go net/http sets Request.ContentLength versus the Content-Length header on incoming requests.
