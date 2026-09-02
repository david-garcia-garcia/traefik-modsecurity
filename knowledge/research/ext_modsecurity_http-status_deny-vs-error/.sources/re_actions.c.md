---
url: https://github.com/owasp-modsecurity/ModSecurity/blob/0875b1928003fa77ad5d2dcd61c531149ded7781/apache2/re_actions.c
title: apache2/re_actions.c
fetched: 2026-09-01
authority: source
ref: owasp-modsecurity/ModSecurity@0875b1928003fa77ad5d2dcd61c531149ded7781:apache2/re_actions.c
---

`deny` init: `intercept_action = ACTION_DENY`.

`status` validate: comment only — “ENH action->param must be a valid HTTP status code.” Returns NULL (accepts the param).

`status` init: `intercept_status = atoi(action->param)`. No range check.

`drop` init: `intercept_action = ACTION_DROP`.
