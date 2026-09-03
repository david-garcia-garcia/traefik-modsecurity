---
url: https://github.com/coreruleset/coreruleset/blob/96d9f99043b89f07fb5a4fdad1d7effbbbbcec1a/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example
title: RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example
fetched: 2026-09-01
authority: source
ref: coreruleset/coreruleset@96d9f99043b89f07fb5a4fdad1d7effbbbbcec1a:rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example
---

Anomaly-mode blocking rules overwrite `SecDefaultAction` with `deny`. “This 'deny' is by default paired with a 'status:403' action.”

“Default action: block with error 403.”

To change after CRS loads: `SecRuleUpdateActionById` on 949110 and 959100. Examples: redirect; `deny,status:404`; `drop`.
