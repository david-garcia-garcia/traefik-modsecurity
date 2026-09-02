---
url: https://www.rfc-editor.org/rfc/rfc9110.html#name-get
title: RFC 9110 HTTP Semantics — GET, HEAD, DELETE content
fetched: 2026-09-01
authority: official
---

Request message framing is independent of the method.

Content received in a GET, HEAD, or DELETE request has no generally defined semantics, cannot alter the meaning or target of the request, and might lead some implementations to reject the request and close the connection because of its potential as a request smuggling attack.

A client SHOULD NOT generate content in a GET, HEAD, or DELETE request unless it is made directly to an origin server that has previously indicated that such a request has a purpose and will be adequately supported.

An origin server SHOULD NOT rely on private agreements to receive content, since participants in HTTP communication are often unaware of intermediaries along the request chain.
