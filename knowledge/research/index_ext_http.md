# ext / http

## WebSocket handshake
priority: normal
local: ext_http_websocket_handshake/
description: RFC 6455 opening handshake and RFC 9110 Connection/Upgrade token lists.

## HTTP/1 client body reuse
priority: normal
local: ext_http_client_body-reuse/
description: When Go's HTTP client can keep an HTTP/1 connection after Close.

## Request.Host
priority: normal
local: ext_http_request_host/
description: How Go net/http exposes inbound Host and what NewRequest and Write send on the wire.

## ReverseProxy X-Forwarded-For
priority: normal
local: ext_http_reverseproxy_x-forwarded-for/
description: How httputil.ReverseProxy appends the peer IP to X-Forwarded-For and what it does with Host and X-Real-IP.
