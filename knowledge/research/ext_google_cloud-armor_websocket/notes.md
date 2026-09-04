# Cloud Armor WebSocket

Cloud Armor evaluates the first HTTP(S) request that opens a WebSocket channel. It does not evaluate messages after that request. Official docs do not skip evaluation because `Upgrade` is present, and they do not tell operators to allowlist WebSocket paths.

## Official: first request only

“How WebSocket connections are handled”: global external Application Load Balancers have built-in WebSocket support. “WebSocket channels are initiated from HTTP(S) requests. Cloud Armor can block a WebSocket channel from being established, for example, if an IP address denylist blocks the client's IP address. However, subsequent transactions in the channel don't conform to the HTTP protocol, and Cloud Armor doesn't evaluate any messages after the first request.”

Owner: [Security policy overview — How WebSocket connections are handled](https://docs.cloud.google.com/armor/docs/security-policy-overview).

Extract: `.sources/security-policy-overview-websocket.md`

## Skip-on-Upgrade

The first request is evaluated. Docs do not say that `Upgrade` / `Connection` without `Sec-WebSocket-*` skip that evaluation. A forged Upgrade that never becomes a channel is still “the first request.”

Owner: same page.

## Operators bypassing paths

No official requirement to exclude WebSocket URLs from the security policy. Operators who want the channel to establish must not block that first HTTP(S) request (example given: IP denylist).
