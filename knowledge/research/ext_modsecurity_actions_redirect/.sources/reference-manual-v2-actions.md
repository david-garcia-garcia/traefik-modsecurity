---
url: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)-Actions
title: Reference Manual (v2.x) Actions
fetched: 2026-09-01
authority: official
---

redirect: Intercepts transaction by issuing an external (client-visible) redirection to the given location. Disruptive.

If the status action is present on the same rule, and its value can be used for a redirection (i.e., is one of the following: 301, 302, 303, or 307), the value will be used for the redirection status code. Otherwise, status code 302 will be used.

status: Specifies the response status code to use with actions deny and redirect. Action Group: Data.

Example: SecDefaultAction "phase:1,log,deny,id:145,status:403"

deny: Stops rule processing and intercepts transaction. Disruptive.

block: Performs the disruptive action defined by the previous SecDefaultAction. Placeholder so administrators choose how to block.
