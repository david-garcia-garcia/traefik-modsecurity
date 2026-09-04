# Fastly Next-Gen WAF WebSocket

Edge and Cloud Next-Gen WAF do not inspect WebSocket traffic. Delivery WebSockets is documented as incompatible with Next-Gen WAF. On-Prem (Core) NGINX module and reverse-proxy agent can inspect WebSocket traffic only when operators turn it on (`sigsci_websocket_enabled` defaults off). Official docs do not describe skipping HTTP inspection because `Upgrade` is present.

## Official: Edge/Cloud cannot inspect WS; Core can

Limitations: “A WAF only inspects HTTP or HTTPS requests (layer 7).” Separate bullet: “WebSocket traffic inspection. Next-Gen WAF can only inspect WebSocket traffic when it is deployed using the Core WAF deployment method. Edge WAF and Cloud WAF deployments don't support WebSocket traffic inspection.”

Owner: [Fastly Next-Gen WAF](https://docs.fastly.com/products/fastly-next-gen-waf).

Extract: `.sources/fastly-next-gen-waf.md`

Deployment guide: module-agent “The only Next-Gen WAF module variation that supports WebSocket inspection is the NGINX dynamic module.” Reverse proxy: “This option supports WebSocket inspection.”

Owner: [About deploying the Next-Gen WAF](https://www.fastly.com/documentation/guides/next-gen-waf/setup-and-configuration/about-deploying-the-next-gen-waf).

Extract: `.sources/about-deploying-ngwaf.md`

## Official: Delivery WebSockets incompatible with NGWAF

“WebSockets is not compatible with shielding or the Fastly Next-Gen WAF.”

Owner: [WebSockets](https://docs.fastly.com/products/websockets).

Extract: `.sources/fastly-websockets.md`

Conflict: product WebSockets page says incompatible with NGWAF; NGWAF page says Core can inspect WS. Follow both: Edge delivery WebSockets + Edge NGWAF do not combine; Core/On-Prem is the inspection path.

## Official: Core inspection is opt-in per location

NGINX dynamic module: `sigsci_websocket_enabled` — “Enable or disable WebSocket inspection”; `on` / `off` (default). “To enable it, it must be specified in the `http` section. Thereafter, it may be turned `off` and `on` in the `server` and `location` sections.” Example: global on, server off, `location /websenabled` on.

Owner: [Installing the NGINX dynamic module](https://www.fastly.com/documentation/guides/next-gen-waf/setup-and-configuration/module-agent-deployment/nginx-module/installing-the-nginx-dynamic-module/).

Extract: `.sources/nginx-dynamic-module-websocket.md`

Client IP for WebSocket inspection must be set on the agent, not only in the control panel.

Owner: [Client IP addresses](https://www.fastly.com/documentation/guides/next-gen-waf/client-ip-addresses).

Extract: `.sources/client-ip-addresses.md`

## Skip-on-Upgrade / handshake

Docs do not say `Upgrade` without `Sec-WebSocket-*` skips HTTP inspection. On Edge, the documented constraint is product incompatibility, not an Upgrade-header bypass. On Core, frame inspection is a separate flag; handshake HTTP is ordinary HTTP unless the operator never sends it to the module.

## Operators bypassing paths

Edge: to use the Delivery WebSockets product, NGWAF is not compatible — that is an architecture split, not a path allowlist. Core: operators must enable `sigsci_websocket_enabled` on the locations they want inspected; default is off.
