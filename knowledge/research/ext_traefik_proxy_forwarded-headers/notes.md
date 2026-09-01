# Forwarded headers

Traefik wraps every HTTP entrypoint with `forwardedheaders.XForwarded` **before** the router switcher (Yaegi middleware). That wrapper may keep, drop, or join incoming `X-Forwarded-*` and always fills `X-Real-Ip` from the peer when empty. It does **not** append `RemoteAddr` to `X-Forwarded-For`. The append happens later, on the hop to the backend.

## Official: trust, then optionally skip the backend append

You can configure Traefik to trust forwarded headers (`X-Forwarded-*`). `forwardedHeaders.trustedIPs` trusts those headers from listed IPs/CIDRs. `forwardedHeaders.insecure` always trusts them (tests only; default `false`).

`forwardedHeaders.notAppendXForwardedFor` (default `false`): when `true`, Traefik will not append the client's `RemoteAddr` to `X-Forwarded-For`. The existing header is preserved as-is. If no `X-Forwarded-For` exists, none will be added.

The official `connection` paragraph is the only place that says *when* a forwarded-headers step runs relative to middleware: Connection-named fields are removed “as soon as the request is handled,” so they are “not available when the request passes through the middleware chain.”

Owner: [Traefik EntryPoints — Forwarded Headers](https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/).

Extract: `.sources/entrypoints-forwarded-headers.md`

## Source: entrypoint wraps the switcher

`traefik/traefik@237f13c677edb45ab696b7347b517e1f6b46b849` (shallow master, 2026-09-01).

`newHTTPServer` builds `next` as `requestdecorator` then `httpSwitcher`, then:

`handler, err = forwardedheaders.NewXForwarded(Insecure, TrustedIPs, Connection, NotAppendXForwardedFor, AddXForwardedSchemeHeaders, next)`

The HTTP server’s `Handler` is that wrapper (plus path/query/content-type wrappers **outside** it). Router middleware, including a Yaegi plugin, is inside `httpSwitcher`. So `XForwarded.ServeHTTP` runs first.

Owner: `traefik/traefik@237f13c:pkg/server/server_entrypoint_tcp.go`.

Extract: `.sources/server_entrypoint_tcp.go.md`

## Source: rewrite before `next` (no RemoteAddr on XFF)

`XForwarded.ServeHTTP`:

1. If not `insecure` and `RemoteAddr` is not a trusted IP, `DeleteXForwardedHeaders` (canonical `X-Forwarded-*` / `X-Real-Ip` and `_` aliases).
2. `rewrite`.
3. `removeConnectionHeaders`.
4. If `notAppendXForwardedFor`, stash `SetNotAppendXFF` on the request context.
5. `next.ServeHTTP`.

`rewrite` when `SplitHostPort(RemoteAddr)` succeeds: strip an IPv6 zone (`%…`), set `X-Real-Ip` to that host **only if empty**. Fill empty `X-Forwarded-Proto` / `X-Forwarded-Port` / `X-Forwarded-Host`. If any `X-Forwarded-For` values remain, `Set` them joined with `", "`. It does not append `clientIP` to `X-Forwarded-For`. Empty `RemoteAddr` in the unit tests leaves XFF empty or as the incoming chain.

Default entrypoint (`insecure=false`, no `trustedIPs`): incoming XFF is deleted; the plugin sees **no** `X-Forwarded-For` and **does** see `X-Real-Ip` = peer host.

Owner: `traefik/traefik@237f13c:pkg/middlewares/forwardedheaders/forwarded_header.go` and `forwarded_header_test.go`.

Extract: `.sources/forwarded_header.go.md`

## Source: backend proxy appends after middleware

`pkg/proxy/httputil` `rewriteRequestBuilder` (stdlib `ReverseProxy` `Rewrite` hook) copies inbound `X-Forwarded-For` onto `Out`, then unless `ShouldNotAppendXFF(ctx)`: `SplitHostPort(In.RemoteAddr)`, join prior values with `", "`, append this hop, `Set`. Same algorithm as stdlib Director (including the nil-slice omit). `pkg/proxy/fast` does the same on the outbound request.

Unit test: inbound `X-Forwarded-For: 1.2.3.4` and `RemoteAddr 127.0.0.1:1234` → backend sees `1.2.3.4, 127.0.0.1`. With the context flag, it stays `1.2.3.4`.

That hop is the **backend**, after the middleware chain. A Yaegi plugin that builds its own sidecar request does not get this append unless it does it itself.

Owner: `traefik/traefik@237f13c:pkg/proxy/httputil/proxy.go`, `proxy_test.go`, `pkg/proxy/fast/proxy.go`.

Extract: `.sources/httputil-proxy.go.md`

Related stdlib algorithm: `knowledge/research/ext_http_reverseproxy_x-forwarded-for/`.
