---
url: https://github.com/coreruleset/coreruleset/blob/96d9f99043b89f07fb5a4fdad1d7effbbbbcec1a/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
title: REQUEST-920-PROTOCOL-ENFORCEMENT.conf Host rules
fetched: 2026-09-01
authority: source
ref: github.com/coreruleset/coreruleset@96d9f99043b89f07fb5a4fdad1d7effbbbbcec1a:rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
---

Inspected from a shallow temp clone of coreruleset/coreruleset master; clone deleted after extract.

Comments: “Missing/Empty Host Header”; “These rules will first check to see if a Host header is present.”

920280: `SecRule &REQUEST_HEADERS:Host "@eq 0"` — msg `Request Missing a Host Header`.

920290: `SecRule REQUEST_HEADERS:Host "@rx ^$"` — msg `Empty Host Header`.

920350: `SecRule REQUEST_HEADERS:Host "@rx (?:^([\d.]+|\[[\da-f:]+\]|[\da-f:]+)(:[\d]+)?$)"` — msg `Host header is a numeric IP address`. Comment: IPv4, IPv6 with brackets, IPv6 without brackets, optional `:port`.

`ver:'OWASP_CRS/4.30.0-dev'` on these rules. No `X-Forwarded-Host` in the three Host checks.
