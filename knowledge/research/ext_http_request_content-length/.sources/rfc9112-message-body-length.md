---
url: https://www.rfc-editor.org/rfc/rfc9112.html#name-message-body-length
title: RFC 9112 HTTP/1.1 Message Body Length
fetched: 2026-09-01
authority: official
---

§6.3 Message Body Length — precedence order (used claims):

Item 3: If a message is received with both Transfer-Encoding and Content-Length, Transfer-Encoding overrides Content-Length. Such a message might indicate request smuggling or response splitting and ought to be handled as an error. An intermediary that chooses to forward MUST first remove the received Content-Length and process Transfer-Encoding before forwarding.

Item 4: If Transfer-Encoding is present and chunked is the final encoding, body length is determined by decoding chunks until complete. A request whose Transfer-Encoding is present and chunked is not the final encoding: server MUST 400 and close.

Item 6: A valid Content-Length without Transfer-Encoding is the expected body length in octets.

Item 7: If this is a request and none of the above are true, the message body length is zero (no message body).

Note: Request messages are never close-delimited; absence of length and transfer coding means the request ends after the header section.
