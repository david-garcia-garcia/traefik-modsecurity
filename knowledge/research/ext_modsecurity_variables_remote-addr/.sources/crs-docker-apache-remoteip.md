---
url: https://github.com/coreruleset/modsecurity-crs-docker/blob/5e3cda3ee7d0e77d70e550df7298c80269776cde/README.md
title: CRS Docker Apache RemoteIP env and vhost
fetched: 2026-09-01
authority: official
ref: coreruleset/modsecurity-crs-docker@5e3cda3ee7d0e77d70e550df7298c80269776cde:apache/conf/extra/httpd-vhosts.conf
---

README Apache ENV Variables:

- REMOTEIP_INT_PROXY: “A string indicating the client intranet IP addresses trusted to present the RemoteIPHeader value (Default: `10.1.0.0/16`)”
- REMOTEIP_HEADER: “A string indicating the header to use for RemoteIPHeader value (Default: `X-Forwarded-For`)”

`apache/Dockerfile-alpine` and `apache/Dockerfile` ENV defaults match those strings. Both uncomment `LoadModule remoteip_module modules/mod_remoteip.so`. Alpine image copies `mod_security2.so` (ModSecurity 2.x Apache module).

`apache/conf/extra/httpd-vhosts.conf`:

```
RemoteIPHeader ${REMOTEIP_HEADER}
RemoteIPInternalProxy ${REMOTEIP_INT_PROXY}
```

Also (outbound to BACKEND, not inbound from Traefik): `RequestHeader set X-Real-IP %{REMOTE_ADDR}s`.
