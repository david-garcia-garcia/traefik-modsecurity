---
url: https://github.com/coreruleset/coreruleset/blob/v4.3.0/CHANGES.md
title: CRS 3.0.1 removed insecure X-Forwarded-For handling
fetched: 2026-09-01
authority: official
---

CHANGES.md, Version 3.0.1 - 2017-05-09:

“SECURITY: Removed insecure handling of X-Forwarded-For header; reported by Christoph Hansen (Walter Hop)”

Earlier CHANGES (pre-3.0) mentioned “Adding in a check for X-Forwarded-For source IP when creating IP collection.” That path was the insecure handling 3.0.1 removed.

Wiki draft for the same release (https://github.com/coreruleset/coreruleset/wiki/Draft-3.0.1-release-message):

“This request header can easily be faked by clients and is no longer being taken into consideration to define the TX.real_ip variable. It is still used in the generation of REMOTE_ADDR. Apache users may want to configure mod_remoteip.”

And: “if you run your ModSecurity behind a proxy that sets the X-Forwarded-For header, your IP collection will probably fail to work properly. You may want to look into mod_remoteip or similar means to fill the variable REMOTE_ADDR correctly.”
