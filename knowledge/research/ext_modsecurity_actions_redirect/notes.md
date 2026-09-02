# ModSecurity redirect and status actions

A triggered ModSecurity rule can intercept the transaction with a client-visible redirect. That is a disrupt, not a pass.

## redirect

`redirect` intercepts the transaction and issues an external redirection to the given location. If `status` is also present and is 301, 302, 303, or 307, that status is used. Otherwise the redirect status is 302.

Owner: [Reference Manual (v2.x) Actions — redirect](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)-Actions).

Extract: `.sources/reference-manual-v2-actions.md`

## status with deny

`status` sets the response status used with `deny` and `redirect`. `SecDefaultAction` may include `deny,status:403` or another status. The manual does not restrict `deny` to 4xx only.

Owner: same Actions page (`status`, `deny`, `SecDefaultAction` examples).

## This product

The sidecar HTTP status is the only block signal in `pkg/modsecurity/serve.go`. A sidecar that implements `redirect` or `deny,status:302` returns 3xx. Usage: `knowledge/devdocs/core_plugin_middleware.md`.
