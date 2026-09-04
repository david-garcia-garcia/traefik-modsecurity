---
url: https://www.rfc-editor.org/rfc/rfc9110.html#name-if-none-match
title: RFC 9110 §13.1.2 If-None-Match
fetched: 2026-09-03
authority: official
---

`If-None-Match` makes the request method conditional on a recipient cache or origin server either not having any current representation of the target resource, when the field value is `*`, or having a selected representation whose entity tag does not match any listed value.

ABNF: `If-None-Match = "*" / #entity-tag`. Example includes `If-None-Match: *`.

Evaluation:

1. If the field value is `*`, the condition is false if the origin server has a current representation for the target resource.
2. If the field value is a list of entity tags, the condition is false if one listed tag matches the selected representation.
3. Otherwise the condition is true.

When the condition is false, the origin MUST NOT perform the method: 304 for GET/HEAD, 412 for other methods.
