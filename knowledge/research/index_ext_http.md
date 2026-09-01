# ext / http

## WebSocket handshake
priority: normal
local: ext_http_websocket_handshake/
description: RFC 6455 opening handshake and RFC 9110 Connection/Upgrade token lists.

## HTTP/1 client body reuse
priority: normal
local: ext_http_client_body-reuse/
description: When Go's HTTP client can keep an HTTP/1 connection after Close.

## Go net/url Parse
priority: normal
local: ext_http_url_parse/
description: How Go parses a raw URL and what IsAbs, Host, and Path mean.

## Go http.Client Timeout
priority: normal
local: ext_http_client_timeout/
description: How Client.Timeout treats zero and negative durations.
