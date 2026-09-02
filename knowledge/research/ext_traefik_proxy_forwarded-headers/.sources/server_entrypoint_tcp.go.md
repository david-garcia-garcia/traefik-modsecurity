---
url: https://github.com/traefik/traefik/blob/237f13c677edb45ab696b7347b517e1f6b46b849/pkg/server/server_entrypoint_tcp.go
title: pkg/server/server_entrypoint_tcp.go newHTTPServer
fetched: 2026-09-01
authority: source
ref: github.com/traefik/traefik@237f13c677edb45ab696b7347b517e1f6b46b849:pkg/server/server_entrypoint_tcp.go
---

Inspected from a shallow temp clone of traefik/traefik master; clone deleted after extract.

`newHTTPServer`:

1. `httpSwitcher := middlewares.NewHandlerSwitcher(http.NotFoundHandler())`
2. `next, err := alice.New(requestdecorator.WrapHandler(reqDecorator)).Then(httpSwitcher)`
3. `handler, err = forwardedheaders.NewXForwarded(configuration.ForwardedHeaders.Insecure, TrustedIPs, Connection, NotAppendXForwardedFor, AddXForwardedSchemeHeaders, next)`
4. Further wrappers (keep-alive, content-type, query semicolons, sanitize/normalize path, deny fragment, alias headers) wrap that `handler`.
5. `http.Server{Handler: handler, ...}`

Router middleware lives under `httpSwitcher`. `XForwarded` is therefore outside the Yaegi plugin and runs first.
