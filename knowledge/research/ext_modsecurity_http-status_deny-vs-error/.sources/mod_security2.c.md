---
url: https://github.com/owasp-modsecurity/ModSecurity/blob/0875b1928003fa77ad5d2dcd61c531149ded7781/apache2/mod_security2.c
title: apache2/mod_security2.c
fetched: 2026-09-01
authority: source
ref: owasp-modsecurity/ModSecurity@0875b1928003fa77ad5d2dcd61c531149ded7781:apache2/mod_security2.c
---

`ACTION_DENY`: if `intercept_status != 0`, that code is sent (`Access denied with code %d`). If `intercept_status == 0`, sends `HTTP_INTERNAL_SERVER_ERROR` (500) with “Invalid status code requested”.

`ACTION_DROP` (non-Windows): successful socket close → `HTTP_FORBIDDEN` (403) and “Access denied with connection close”. Failed close → 500.

Misconfigured `proxy` action also returns 500 with “Configuration Error”.
