# Traefik Hub WAF WebSocket

Traefik Hub’s Coraza WAF middleware docs describe HTTP SecLang / CRS directives only. They do not mention WebSocket, Upgrade, or skipping inspection on handshake-shaped headers. Proxy-level Upgrade restore is already in [Proxy upgrade headers](../ext_traefik_proxy_upgrade-headers/notes.md); this folder is the WAF product silence.

## Official: WAF middleware is Coraza HTTP rules

“The Coraza WAF middleware in Traefik Hub API Gateway provides web application firewall capabilities.” Examples: `SecRule REQUEST_URI`, `SecRuleEngine On`, CRS includes `REQUEST-911-METHOD-ENFORCEMENT` and `REQUEST-949-BLOCKING-EVALUATION`. Options: `directives`, `crsEnabled`. No WebSocket, Upgrade, or 101.

Owner: [Coraza Web Application Firewall - Traefik](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/waf/).

Extract: `.sources/traefik-hub-waf.md`

Hub duplicate: same middleware, same two options, same silence.

Owner: [Coraza Web Application Firewall | Traefik Hub](https://doc.traefik.io/traefik-hub/api-gateway/reference/routing/http/middlewares/ref-coraza-waf).

## Official: WebSocket guide is routing, not WAF

Traefik WebSocket user guide: WS/WSS “out of the box”, Headers middleware for Origin, TLS. No WAF, no skip-on-Upgrade.

Owner: [Traefik WebSocket Documentation](https://doc.traefik.io/traefik/v3.4/user-guides/websocket/) (versioned guide still published).

Extract: `.sources/traefik-websocket-guide.md`

## Inference: handshake follows Coraza HTTP, not a Traefik skip

Hub WAF is Coraza. Coraza inspects the upgrade request and does not skip on Upgrade ([Coraza WAF WebSocket](../ext_coraza_waf_websocket/notes.md)). Traefik’s own WAF pages do not add a conflicting skip.

Authority: inference from the Hub WAF page plus the Coraza finding.

## Operators bypassing paths

Official WAF pages do not tell operators to exclude WebSocket routers from the middleware.
