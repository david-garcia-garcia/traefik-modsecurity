---
url: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)-Configuration-Directives
title: Reference Manual (v2.x) Configuration Directives
fetched: 2026-09-01
authority: official
---

`SecDefaultAction` default: `phase:2,log,auditlog,pass`.

Example usage: `SecDefaultAction "phase:2,log,auditlog,deny,status:403,tag:'SLA 24/7'"`.

Must specify a disruptive action and a phase. Not inherited across configuration contexts.

`SecRule` with no actions uses the default list. Rule actions merge with and overwrite the default list.

`SecRuleUpdateActionById` example: `"deny,status:403"`.

`SecRuleEngine DetectionOnly` never executes disruptive actions (block, deny, drop, allow, proxy, redirect).
