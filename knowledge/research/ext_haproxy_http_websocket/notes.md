# HAProxy HTTP WebSocket

HAProxy treats 101 as a protocol switch into tunnel mode. After that it no longer processes HTTP messages on the connection. By default it rejects WebSocket requests missing `Sec-WebSocket-Key`; `option accept-unsafe-violations-in-http-request` relaxes that. Official WAF module pages do not claim frame inspection or an Upgrade-header WAF skip.

## Official: 101 switches to tunnel

“Status 101 messages indicate that the protocol is changing over the same connection and that HAProxy must switch to tunnel mode, just as if a CONNECT had occurred. Then the Upgrade header would contain additional information about the type of protocol the connection is switching to.”

Owner: [HAProxy Enterprise Configuration Manual](https://www.haproxy.com/documentation/haproxy-configuration-manual/latest/).

Extract: `.sources/haproxy-config-101-tunnel.md`

## Official: missing Sec-WebSocket-Key is invalid unless relaxed

`option accept-unsafe-violations-in-http-request`: “By default, HAProxy complies with the different HTTP RFCs in terms of message parsing.” When the option is set, “In H1 only, WebSocket (RFC6455) requests failing to present a valid \"Sec-Websocket-Key\" header field will be accepted.” “This option should never be enabled by default as it hides application bugs and open security breaches.”

Matching response option accepts responses missing `Sec-Websocket-Accept`.

Owner: same Configuration Manual (`option accept-unsafe-violations-in-http-request` / `-response`).

Extract: `.sources/haproxy-accept-unsafe-websocket.md`

Enterprise 3.2r1 release notes repeat that those directives “allow HAProxy Enterprise to accept WebSocket requests that are missing the `Sec-WebSocket-Key` HTTP header and responses missing the `Sec-WebSocket-Accept` HTTP header.”

Owner: [HAProxy Enterprise release notes](https://www.haproxy.com/documentation/haproxy-enterprise/release-notes/).

## Skip-on-Upgrade / WAF

Tunnel after **successful 101**, not after seeing `Upgrade` on a request that never switches. A GET with Upgrade and no key is rejected by default (not skipped). Official WAF release notes describe `http-request waf-evaluate` and WAF profiles as HTTP request actions; they do not say WAF inspects WebSocket frames or that Upgrade skips WAF.

Owner: [HAProxy Enterprise release notes](https://www.haproxy.com/documentation/haproxy-enterprise/release-notes/).

Extract: `.sources/haproxy-waf-release-notes.md`

## Operators bypassing paths

Official config does not require WAF-off for WebSocket backends. Operators who need non-RFC handshakes (no Sec-WebSocket-Key) must opt in to `accept-unsafe-violations-in-http-request`.
