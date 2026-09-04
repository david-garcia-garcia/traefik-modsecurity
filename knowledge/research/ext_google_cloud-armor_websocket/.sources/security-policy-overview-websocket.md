---
url: https://docs.cloud.google.com/armor/docs/security-policy-overview
title: Security policy overview | Google Cloud Armor
fetched: 2026-09-03
authority: official
---

How WebSocket connections are handled: Global external Application Load Balancers have built-in support for the WebSocket protocol. WebSocket channels are initiated from HTTP(S) requests. Cloud Armor can block a WebSocket channel from being established, for example if an IP address denylist blocks the client's IP address. Subsequent transactions in the channel don't conform to the HTTP protocol, and Cloud Armor doesn't evaluate any messages after the first request.
