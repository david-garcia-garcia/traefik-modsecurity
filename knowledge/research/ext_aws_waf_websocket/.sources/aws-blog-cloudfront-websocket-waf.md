---
url: https://aws.amazon.com/blogs/networking-and-content-delivery/private-ai-agent-with-websocket-streaming-over-cloudfront-vpc-origins-and-the-next-generation-of-opensearch-serverless-for-knowledge-retrieval/
title: Private AI agent with WebSocket streaming over CloudFront VPC Origins
fetched: 2026-09-03
authority: vendor
---

When a WebSocket connection is established, the HTTP upgrade request passes through the attached AWS WAF web ACL, so the connection attempt can hit rule groups and custom conditions before the persistent connection opens.

The WebSocket upgrade is a GET with no body. The AWS managed common rule set tends to block it (403 on the handshake). The blog’s fix is a high-priority WAF rule that allows requests carrying Upgrade: websocket before managed groups evaluate them, so managed protections still apply to normal traffic.
