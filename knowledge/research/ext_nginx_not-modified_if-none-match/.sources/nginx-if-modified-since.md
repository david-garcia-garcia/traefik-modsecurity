---
url: https://nginx.org/en/docs/http/ngx_http_core_module.html#if_modified_since
title: nginx ngx_http_core_module if_modified_since
fetched: 2026-09-03
authority: official
---

Syntax: `if_modified_since off | exact | before;` Default: `if_modified_since exact;` Context: `http`, `server`, `location`. Appeared in 0.7.24.

Specifies how to compare modification time of a response with the time in the “If-Modified-Since” request header field.

`off` (0.7.34): the response is always considered modified.

`exact`: exact match.

`before`: modification time of the response is less than or equal to the time in If-Modified-Since.

Does not mention If-None-Match.
