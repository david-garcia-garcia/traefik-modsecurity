---
url: https://github.com/david-garcia-garcia/traefik-middleware-utilities/blob/v1.0.3/reclaim/yaegi_test.go
title: Yaegi reclaim tests and production imports
fetched: 2026-09-16
authority: source
ref: github.com/david-garcia-garcia/traefik-middleware-utilities@950b08de:reclaim/
---

Production reclaim/*.go (non-_test): table.go imports context, fmt, log/slog, sync, time only.
opentyped.go imports context, fmt, log/slog only.

yaegi_test.go evalHookprobe: "evaluates expr in a GOPATH interp with stdlib only (no unsafe)".
writeGopathReclaim copies non-test .go from reclaim/ into GOPATH for interpretation.

TestYaegi_OpenHooksRunSleepWakeClose, TestYaegi_GraceExpireDoesNotHang, TestYaegi_OpenTypedCallExpressionReturnsT exercise Open/Hooks/AfterFunc under Yaegi.
