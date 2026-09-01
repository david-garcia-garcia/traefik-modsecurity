---
url: https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/
title: Traefik EntryPoints — forwardedHeaders.connection
fetched: 2026-09-01
authority: official
---

Table: `forwardedHeaders.connection` — "List of Connection headers that are allowed to pass through the middleware chain before being removed." Default empty. Not required.

Section `forwardedHeaders.connection`:

As per RFC7230, Traefik respects the Connection options from the client request. It removes any header field(s) listed in the request Connection header and the Connection header field itself when empty. The removal happens as soon as the request is handled by Traefik, thus the removed headers are not available when the request passes through the middleware chain. The `connection` option lists the Connection headers allowed to passthrough the middleware chain before their removal.

Example allow-list value in the fetched page: `foobar`.
