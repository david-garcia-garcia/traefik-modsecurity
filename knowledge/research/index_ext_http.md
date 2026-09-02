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

## Go net/url Parse
priority: normal
local: ext_http_url_parse/
description: How Go parses a raw URL and what IsAbs, Host, and Path mean.

## Go http.Client Timeout
priority: normal
local: ext_http_client_timeout/
description: How Client.Timeout treats zero and negative durations.

## Request context cancellation
priority: normal
local: ext_http_client_request-context/
description: When Go's HTTP client cancels an in-flight request if Request.Context is canceled.

## Request.Host
priority: normal
local: ext_http_request_host/
description: How Go net/http exposes inbound Host and what NewRequest and Write send on the wire.

## ReverseProxy X-Forwarded-For
priority: normal
local: ext_http_reverseproxy_x-forwarded-for/
description: How httputil.ReverseProxy appends the peer IP to X-Forwarded-For and what it does with Host and X-Real-IP.
