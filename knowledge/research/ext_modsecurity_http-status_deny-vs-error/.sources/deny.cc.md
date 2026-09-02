---
url: https://github.com/owasp-modsecurity/ModSecurity/blob/7ea9fefbe0ba409d8733b4d682c8c4c059cd028d/src/actions/disruptive/deny.cc
title: src/actions/disruptive/deny.cc
fetched: 2026-09-01
authority: source
ref: owasp-modsecurity/ModSecurity@7ea9fefbe0ba409d8733b4d682c8c4c059cd028d:src/actions/disruptive/deny.cc
---

`Deny::evaluate` sets `m_it.disruptive = true`.

If `transaction->m_it.status == 200`, it assigns `403`. A prior `status` action that already set a non-200 code (including 500) is left unchanged.
