---
url: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html
title: Listeners for your Application Load Balancers
fetched: 2026-09-03
authority: official
---

Application Load Balancers provide native support for WebSockets. Upgrade an existing HTTP/1.1 connection into ws or wss using an HTTP connection upgrade. When you upgrade, the TCP connection used for requests (to the load balancer and to the target) becomes a persistent WebSocket connection between the client and the target through the load balancer.

Listener options apply to WebSocket connections as well as HTTP traffic. WebSockets are not supported for requests routed to target groups that have enabled target optimizer.
