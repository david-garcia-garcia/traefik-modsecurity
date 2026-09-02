---
url: https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html
title: Apache Module mod_remoteip
fetched: 2026-09-01
authority: official
---

Description: “Replaces the original client IP address for the connection with the useragent IP address list presented by a proxies or a load balancer via the request headers.”

The module overrides the client IP with the address in `RemoteIPHeader`. That overridden address is then used for `Require ip`, `mod_status`, and `%a` / `core` `%a`. The underlying TCP peer remains available as `%{c}a` and `CONN_REMOTE_ADDR`.

“It is critical to only enable this behavior from intermediate hosts (proxies, etc) which are trusted by this server, since it is trivial for the remote useragent to impersonate another useragent.”

`RemoteIPHeader` default: none. “Unless these other directives are used, mod_remoteip will trust all hosts presenting a RemoteIPHeader IP value.”

`RemoteIPInternalProxy`: intranet addresses trusted to present the header; unlike `RemoteIPTrustedProxy`, private addresses in the header are accepted from those proxies.

Multiple comma-delimited IPs: processed right-to-left; halt at the first address not trusted to present the preceding address.

Internal (private) addresses 10/8, 172.16/12, 192.168/16, 169.254/16, 127/8 are only evaluated when `RemoteIPInternalProxy` internal proxies are registered.
