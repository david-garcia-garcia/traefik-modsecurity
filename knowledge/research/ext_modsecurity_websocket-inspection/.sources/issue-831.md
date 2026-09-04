---
url: https://github.com/owasp-modsecurity/ModSecurity/issues/831
title: Modsecurity and websockets
fetched: 2026-09-03
authority: vendor
---

Reporter: Modsecurity forces status code 200 instead of 101. WebSockets doesn't work.

Issue is referenced from #1368. Maintainers do not describe a handshake skip; they say ModSecurity understands HTTP requests only.
