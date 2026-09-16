# Test coverage

1. [hard] Ticket job unproven — `zzz_modsecurity_test.go` (and 18 sibling `git mv` hunks) — ticket job (requirement Desired / proposal Why / SHALL): every product `*_test.go` basename starts with `zzz_` and still ends with `_test.go`; production hunk is rename-only (`modsecurity_test.go` → `zzz_modsecurity_test.go`, 100% similarity; same for the other 18); grepped assertion of that prefix: `(none)` — `TestModsecurity_ServeHTTP` still asserts ServeHTTP status/body and stays green if the 19 renames are reverted
   → Assert every product `*_test.go` basename matches `zzz_*_test.go` (exclude `.agents/`)
   Status: done
   Argument: added `TestProductGoTestFiles_HaveZzzPrefix` in `zzz_test_file_prefix_test.go` (`9ec22d3`).
