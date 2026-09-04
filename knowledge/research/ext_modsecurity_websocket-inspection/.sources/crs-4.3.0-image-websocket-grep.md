---
url: docker://owasp/modsecurity-crs:4.3.0-apache-alpine-202406090906
title: OWASP CRS 4.3.0 Apache image — websocket grep and REQUEST-920 Connection
fetched: 2026-09-03
authority: source
ref: owasp/modsecurity-crs:4.3.0-apache-alpine-202406090906:/etc/modsecurity.d/owasp-crs/rules
---

`grep -RIn -i websocket /etc/modsecurity.d/owasp-crs/rules` — no matches.

REQUEST-920-PROTOCOL-ENFORCEMENT.conf around line 330: comment that the rule inspects the Connection header for duplicates of keep-alive or close.

SecRule REQUEST_HEADERS:Connection `@rx \b(?:keep-alive|close),\s?(?:keep-alive|close)\b`

msg: Multiple/Conflicting Connection Header Data Found.

No SecRule in that file (from this grep of upgrade/websocket in REQUEST-920 and REQUEST-921) matches the websocket protocol token.
