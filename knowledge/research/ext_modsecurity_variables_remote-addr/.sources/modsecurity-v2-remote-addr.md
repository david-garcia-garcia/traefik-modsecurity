---
url: https://github.com/owasp-modsecurity/ModSecurity/blob/0875b1928003fa77ad5d2dcd61c531149ded7781/apache2/re_variables.c
title: ModSecurity v2 REMOTE_ADDR generate and transaction init
fetched: 2026-09-01
authority: source
ref: owasp-modsecurity/ModSecurity@0875b1928003fa77ad5d2dcd61c531149ded7781:apache2/re_variables.c
---

Inspected from a shallow temp clone of owasp-modsecurity/ModSecurity branch v2/master. Clone deleted after extract.

`apache2/mod_security2.c` transaction init:

```
#if AP_SERVER_MAJORVERSION_NUMBER > 1 && AP_SERVER_MINORVERSION_NUMBER < 3
    msr->remote_addr = r->connection->remote_ip;
#else
    msr->remote_addr = r->connection->client_ip;
    msr->useragent_ip = r->useragent_ip;
#endif
```

`apache2/re_variables.c` `var_remote_addr_generate`:

```
#if AP_SERVER_MAJORVERSION_NUMBER > 1 && AP_SERVER_MINORVERSION_NUMBER > 3
    if (ap_find_linked_module("mod_remoteip.c") != NULL) {
        if(msr->r->useragent_ip != NULL) msr->remote_addr = apr_pstrdup(msr->mp, msr->r->useragent_ip);
        return var_simple_generate(var, vartab, mptmp, msr->remote_addr);
    }
#endif
    return var_simple_generate(var, vartab, mptmp, msr->remote_addr);
```

No read of `X-Forwarded-For` / `REQUEST_HEADERS` in this generator. `USERAGENT_IP` returns `msr->useragent_ip` (or `0.0.0.0`).
