---
url: https://www.fastly.com/documentation/guides/next-gen-waf/setup-and-configuration/module-agent-deployment/nginx-module/installing-the-nginx-dynamic-module/
title: Installing the NGINX dynamic module
fetched: 2026-09-03
authority: official
---

sigsci_websocket_enabled: Enable or disable WebSocket inspection. Values on / off (default off). Contexts: http, server, or per location.

Must be specified on in the http section first. Then it may be turned off and on in server and location.

Example: http { sigsci_websocket_enabled on; } server { sigsci_websocket_enabled off; location /websenabled { sigsci_websocket_enabled on; proxy_pass http://websocket; } }
