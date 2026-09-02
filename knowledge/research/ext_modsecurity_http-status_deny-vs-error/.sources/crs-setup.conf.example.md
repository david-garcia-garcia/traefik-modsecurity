---
url: https://github.com/coreruleset/coreruleset/blob/96d9f99043b89f07fb5a4fdad1d7effbbbbcec1a/crs-setup.conf.example
title: crs-setup.conf.example
fetched: 2026-09-01
authority: source
ref: coreruleset/coreruleset@96d9f99043b89f07fb5a4fdad1d7effbbbbcec1a:crs-setup.conf.example
---

Anomaly scoring (default): blocking evaluation returns **error 403**. Shipped `SecDefaultAction` for phases 1–5 is `log,auditlog,pass`.

Self-contained example (commented): `deny,status:403`. Comment: other statuses such as 404, 406, etc. are allowed.

Redirect example (commented): `redirect:'http://%{request_headers.host}/'`.

Change disruptive action via `RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example`. Apache `ErrorDocument` can replace the 403 page.
