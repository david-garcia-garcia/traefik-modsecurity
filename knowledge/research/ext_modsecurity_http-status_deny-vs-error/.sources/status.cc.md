---
url: https://github.com/owasp-modsecurity/ModSecurity/blob/7ea9fefbe0ba409d8733b4d682c8c4c059cd028d/src/actions/data/status.cc
title: src/actions/data/status.cc
fetched: 2026-09-01
authority: source
ref: owasp-modsecurity/ModSecurity@7ea9fefbe0ba409d8733b4d682c8c4c059cd028d:src/actions/data/status.cc
---

`Status::init` parses the payload with `std::stoi`. Failure only if it is not a number.

`Status::evaluate` assigns `transaction->m_it.status = m_status` with no 4xx/5xx range check.
