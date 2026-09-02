---
url: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)-Actions
title: Reference Manual (v2.x) Actions
fetched: 2026-09-01
authority: official
---

`block` performs the disruptive action from the previous `SecDefaultAction`. Examples set that policy as `deny,status:403`.

`deny`: stops rule processing and intercepts the transaction. Example has no `status` on the rule itself.

`drop`: immediate TCP close (FIN). v2 only; not on Windows builds. Minimizes bandwidth vs returning a body. Logs “(9)Bad file descriptor: core_output_filter…”.

`redirect`: client-visible redirect. If `status` is 301, 302, 303, or 307, that code is used; otherwise 302.

`status`: “Specifies the response status code to use with actions deny and redirect.” Example: `SecDefaultAction "phase:1,log,deny,id:145,status:403"`. Apache `ErrorDocument` for that status runs if configured. Phase 1 status can supersede Apache Directory/Location status settings.

No 4xx-only restriction is stated for `status` on `deny`.
