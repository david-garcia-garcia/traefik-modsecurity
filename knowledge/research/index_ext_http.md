# ext / http

## WebSocket handshake
priority: normal
local: ext_http_websocket_handshake/
description: RFC 6455 opening handshake and RFC 9110 Connection/Upgrade token lists.

## HTTP/1 client body reuse
priority: normal
local: ext_http_client_body-reuse/
description: When Go's HTTP client can keep an HTTP/1 connection after Close.

## HTTP method request content
priority: normal
local: ext_http_methods_request-content/
description: RFC 9110 rules for request content on GET, HEAD, and DELETE.
