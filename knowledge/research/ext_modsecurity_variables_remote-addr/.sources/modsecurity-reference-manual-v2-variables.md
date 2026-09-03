---
url: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v2.x)-Variables
title: Reference Manual (v2.x) Variables — REMOTE_ADDR and USERAGENT_IP
fetched: 2026-09-01
authority: official
---

REMOTE_ADDR: “This variable holds the IP address of the remote client.”

Example: `SecRule REMOTE_ADDR "@ipMatch 192.168.1.101" "id:35"`

USERAGENT_IP: “This variable is created when running modsecurity with apache2.4 and will contains the client ip address set by mod_remoteip in proxied connections.” Version 2.x. Supported on libModSecurity: TBI.

REQUEST_HEADERS_NAMES example still treats `x-forwarded-for` as a header **name** (`msg:'Proxy Server Used'`), not as REMOTE_ADDR.
