# Outside-system findings

## http
priority: normal
local: index_ext_http.md
description: Official HTTP and WebSocket handshake rules this product relies on.

## nginx
priority: normal
local: index_ext_nginx.md
description: Official nginx HTTP filter and proxy behavior this product relies on.

## traefik
priority: normal
local: index_ext_traefik.md
description: Official Traefik proxy behavior this product relies on.

## geoblock
priority: normal
local: index_ext_geoblock.md
description: Traefik geoblock plugin public config used as a pattern.

## golangci-lint
priority: normal
local: index_ext_golangci-lint.md
description: Official golangci-lint runner and GitHub Action this product can add to CI.

## golang
priority: normal
local: index_ext_golang.md
description: Official Go standard library behavior this product relies on.

## modsecurity
priority: normal
local: index_ext_modsecurity.md
description: Official ModSecurity, OWASP CRS, Apache/nginx sidecar HTTP status, and CRS rule inputs this product forwards to a WAF sidecar.

## authelia
priority: normal
local: index_ext_authelia.md
description: Official Authelia portal HTTP API this product may sit in front of.

## dnastack
priority: normal
local: index_ext_dnastack.md
description: Named DNAstack fork of this plugin (bypass-rules and related commit internals).

## cloudflare
priority: normal
local: index_ext_cloudflare.md
description: Official Cloudflare WAF and Network WebSocket behavior this product compares to.

## aws
priority: normal
local: index_ext_aws.md
description: Official AWS WAF, ALB, CloudFront, and API Gateway WebSocket behavior this product compares to.

## coraza
priority: normal
local: index_ext_coraza.md
description: Official Coraza WAF HTTP middleware behavior this product compares to.

## google
priority: normal
local: index_ext_google.md
description: Official Google Cloud Armor WebSocket evaluation this product compares to.

## fastly
priority: normal
local: index_ext_fastly.md
description: Official Fastly Next-Gen WAF WebSocket inspection this product compares to.

## azure
priority: normal
local: index_ext_azure.md
description: Official Azure Front Door and Application Gateway WAF WebSocket behavior this product compares to.

## haproxy
priority: normal
local: index_ext_haproxy.md
description: Official HAProxy HTTP upgrade and tunnel behavior this product compares to.
