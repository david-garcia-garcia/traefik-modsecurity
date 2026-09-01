# ext / modsecurity

## REMOTE_ADDR
priority: normal
local: ext_modsecurity_variables_remote-addr/
description: How ModSecurity exposes the client IP and how CRS initializes IP collections.

## Host
priority: normal
local: ext_modsecurity_variables_host/
description: How ModSecurity and CRS read the HTTP Host header.
