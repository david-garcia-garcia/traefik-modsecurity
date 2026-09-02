---
url: https://github.com/coreruleset/coreruleset/blob/386f8db6e5f21ed8f0dc9fe8d15d4f59dd213d7a/rules/REQUEST-901-INITIALIZATION.conf
title: REQUEST-901-INITIALIZATION.conf IP collection
fetched: 2026-09-01
authority: source
ref: github.com/coreruleset/coreruleset@386f8db6e5f21ed8f0dc9fe8d15d4f59dd213d7a:rules/REQUEST-901-INITIALIZATION.conf
---

Inspected from a shallow temp clone of coreruleset/coreruleset tag v4.3.0 (`386f8db`). Same rule shape on later master `@96d9f99043b89f07fb5a4fdad1d7effbbbbcec1a` (`ver:'OWASP_CRS/4.30.0-dev'`). Clones deleted after extract.

Comment: “Create both Global and IP collections… IP collection is initialized with the IP address concatened with the hashed user agent.”

Rule 901320 (`ver:'OWASP_CRS/4.3.0'`), gated on `TX:ENABLE_DEFAULT_COLLECTIONS`:

```
initcol:global=global,\
initcol:ip=%{remote_addr}_%{MATCHED_VAR}
```

No `X-Forwarded-For`, `REQUEST_HEADERS:X-Forwarded-For`, or `tx.real_ip` in this file.

`rules/REQUEST-905-COMMON-EXCEPTIONS.conf`: `SecRule REMOTE_ADDR "@ipMatch 127.0.0.1,::1"`.

