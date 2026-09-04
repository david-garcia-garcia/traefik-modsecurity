---
url: https://docs.fastly.com/products/fastly-next-gen-waf
title: Fastly Next-Gen WAF
fetched: 2026-09-03
authority: official
---

Limitations of all WAFs including Next-Gen WAF: inspection of HTTP and HTTPS traffic only (layer 7); will not process TCP, UDP, or ICMP.

WebSocket traffic inspection: Next-Gen WAF can only inspect WebSocket traffic when deployed using the Core WAF deployment method. Edge WAF and Cloud WAF deployments don't support WebSocket traffic inspection.

On-Prem WAF (formerly Core WAF): module plus agent, or agent in reverse proxy mode.
