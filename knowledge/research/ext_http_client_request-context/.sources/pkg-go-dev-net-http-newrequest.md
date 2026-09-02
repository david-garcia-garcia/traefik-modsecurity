---
url: https://pkg.go.dev/net/http#NewRequest
title: net/http NewRequest / NewRequestWithContext
fetched: 2026-09-01
authority: official
---

NewRequest wraps NewRequestWithContext using context.Background.

NewRequestWithContext returns a new Request given a method, URL, and optional body.

For an outgoing client request, the context controls the entire lifetime of a request and its response: obtaining a connection, sending the request, and reading the response headers and body.

To make a request with a specified context.Context, use NewRequestWithContext and Client.Do.
