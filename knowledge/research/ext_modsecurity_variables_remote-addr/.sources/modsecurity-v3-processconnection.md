---
url: https://github.com/owasp-modsecurity/ModSecurity/blob/7ea9fefbe0ba409d8733b4d682c8c4c059cd028d/src/transaction.cc
title: libModSecurity v3 processConnection sets REMOTE_ADDR
fetched: 2026-09-01
authority: source
ref: owasp-modsecurity/ModSecurity@7ea9fefbe0ba409d8733b4d682c8c4c059cd028d:src/transaction.cc
---

Inspected from a shallow temp clone of owasp-modsecurity/ModSecurity default branch. Clone deleted after extract.

`Transaction::processConnection(const char *client, int cPort, const char *server, int sPort)`:

- Comment: call at the very beginning of a request, when the connection arrives; `client` is “Client's IP address in text format.”
- `m_clientIpAddress = client`
- `m_variableRemoteAddr.set(m_clientIpAddress, m_variableOffset)`
- Also sets REMOTE_HOST from the same client string (v3 synonym).

The engine does not parse `X-Forwarded-For`. The connector must pass the IP the web server considers the client.
