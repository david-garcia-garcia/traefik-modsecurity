---
url: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)
title: Reference Manual (v3.x)
fetched: 2026-09-01
authority: official
---

`SecDefaultAction` default still `phase:2,log,auditlog,pass`. Example uses `deny,status:403`.

`deny`: same as v2 — intercept, stop processing.

`drop`: “Unlike in v2, in ModSecurity v3 this action currently functions the same as the deny action.”

`status`: same wording — response status for deny and redirect. Example `status:403`.

Official examples that pair deny with 500:

- `SecRule HIGHEST_SEVERITY "@le 2" "phase:2,id:23,deny,status:500,msg:'severity %{HIGHEST_SEVERITY}'"`
- `SecRule ARGS "@pm some key words" "id:12345,deny,status:500"`

Other official examples use `deny,status:400` and `deny,status:403`.
