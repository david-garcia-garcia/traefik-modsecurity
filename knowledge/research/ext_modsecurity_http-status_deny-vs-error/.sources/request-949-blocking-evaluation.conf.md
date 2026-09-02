---
url: https://github.com/coreruleset/coreruleset/blob/96d9f99043b89f07fb5a4fdad1d7effbbbbcec1a/rules/REQUEST-949-BLOCKING-EVALUATION.conf
title: REQUEST-949-BLOCKING-EVALUATION.conf
fetched: 2026-09-01
authority: source
ref: coreruleset/coreruleset@96d9f99043b89f07fb5a4fdad1d7effbbbbcec1a:rules/REQUEST-949-BLOCKING-EVALUATION.conf
---

Rules 949111 (phase 1, early blocking) and 949110 (phase 2) apply `deny` when inbound anomaly score reaches the threshold.

No `status:` on those rules. CRS 999 example file states this deny is paired with `status:403` by default.

Outbound counterpart: `RESPONSE-959-BLOCKING-EVALUATION.conf` rules 959101 / 959100, also `deny` without `status`.
