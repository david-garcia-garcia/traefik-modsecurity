# HTTP method request content

RFC 9110 treats message framing as independent of method. GET, HEAD, and DELETE may carry content on the wire, but that content has no generally defined semantics. Clients SHOULD NOT send it unless the origin has already said it will support it. Intermediaries may reject it. OPTIONS may define content later; TRACE and CONNECT must not have a body in the usual sense.

## GET, HEAD, DELETE

Owner: [RFC 9110 §9.3.1 GET](https://www.rfc-editor.org/rfc/rfc9110.html#name-get), [§9.3.2 HEAD](https://www.rfc-editor.org/rfc/rfc9110.html#name-head), [§9.3.5 DELETE](https://www.rfc-editor.org/rfc/rfc9110.html#name-delete).

Content in those requests cannot change the meaning or target of the request. Some implementations reject the request and close the connection because of request-smuggling risk. There is no MUST for a server to reject; reading-and-ignoring and 400 are both compliant.

Extract: `.sources/rfc9110-get-head-delete.md`

## This product

This product uses `denyVerbsWithBody` (default includes GET, HEAD, and DELETE). A body on those methods is HTTP 400. An explicit empty list inspects and forwards like POST. Usage: `knowledge/devdocs/core_plugin_middleware.md`.
