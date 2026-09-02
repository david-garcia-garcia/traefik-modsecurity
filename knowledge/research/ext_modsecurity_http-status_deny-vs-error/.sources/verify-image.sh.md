---
url: https://github.com/coreruleset/modsecurity-crs-docker/blob/5e3cda3ee7d0e77d70e550df7298c80269776cde/tests/verify-image.sh
title: tests/verify-image.sh
fetched: 2026-09-01
authority: source
ref: coreruleset/modsecurity-crs-docker@5e3cda3ee7d0e77d70e550df7298c80269776cde:tests/verify-image.sh
---

Image check “attack request is blocked” expects HTTP **403** for `/?test=../../etc/passwd`.

Nginx variant also asserts CORS headers on that 403.
