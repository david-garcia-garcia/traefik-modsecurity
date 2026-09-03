## prepare (2026-09-03)

phase: prepare
findings: none
fixed: none
skipped: CRS overlay not implemented; allow-path throughput not measured (before/after belongs on later cards)

## explore (2026-09-03)

phase: explore
findings: nginx return 200 skips CRS (URI+body); Apache /healthz rewrite still inspects; Range 416 also on tiny 200
fixed: none
skipped: overlay not implemented; after-change throughput not measured

## propose (2026-09-03)

phase: propose
findings: none
fixed: none
skipped: overlay not implemented



## implement (2026-09-03)

phase: implement
findings: four-stack suite kept; nginx drain is loopback server not nc; Test-Integration finally leaked docker compose ps into exit code (fixed)
fixed: inspect-only overlays; Pester benches all four stacks; runner exit code
skipped: CI not seen on this head yet; code review not started
