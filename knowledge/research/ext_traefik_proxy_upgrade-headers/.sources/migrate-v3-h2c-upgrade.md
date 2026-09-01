---
url: https://doc.traefik.io/traefik/migrate/v3/
title: Migration v3.7.13 — h2c Upgrade Requests
fetched: 2026-09-01
authority: official
---

Starting with v3.7.13, Traefik does not forward the Upgrade: h2c and HTTP2-Settings request headers to the backends anymore.

Traefik does not implement the deprecated h2c upgrade mechanism; it only serves unencrypted HTTP/2 with prior knowledge. Forwarding those headers let a backend accept an upgrade that Traefik itself had not negotiated with the client.

A backend that used to accept such an upgrade now serves those requests over HTTP/1.1. To reach a backend over unencrypted HTTP/2, declare servers with the h2c scheme (`h2c://…`, label `loadbalancer.server.scheme=h2c`, CRD `scheme: h2c`, or Ingress annotation `serversscheme: h2c`).
