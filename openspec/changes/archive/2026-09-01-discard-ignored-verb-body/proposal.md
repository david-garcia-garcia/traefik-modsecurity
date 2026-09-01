## Why

Default `ignoreBodyForVerbs` skips sending GET/DELETE/OPTIONS (and HEAD/TRACE/CONNECT) bodies to ModSecurity but still forwards the original `req.Body` to the backend. README says that body is consumed and never reaches the backend. Operators who trust that text leave an uninspected payload path on the default config.

## What Changes

- When the request method is on `ignoreBodyForVerbs` and `ignoreBodyForVerbsDeny` is false, consume the request body and replace it with an empty body before calling `next`. The WAF request stays body-less.
- Zero `ContentLength` and remove the `Content-Length` header so Traefik does not advertise a body that is gone.
- Align README `ignoreBodyForVerbs` with that contract.
- Keep `ignoreBodyForVerbsDeny` default `false`. Do not change the default verb list.

## Capabilities

### New Capabilities

- `core_plugin_middleware_ignored-verb-body`: When a method is on `ignoreBodyForVerbs`, discard the request body so it does not reach the backend, and still omit it from the ModSecurity request.

### Modified Capabilities

None.

## Impact

- `pkg/modsecurity/serve.go` — ignore-verb path consumes and replaces `req.Body`.
- `README.md` — operator contract for `ignoreBodyForVerbs`.
- Unit tests for GET/DELETE (and deny=true / POST control).
- `knowledge/devdocs/core_plugin_middleware.md` — pass-path body rule for ignored verbs.
