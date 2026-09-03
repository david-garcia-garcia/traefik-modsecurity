## pullrequest (2026-09-03T05:43:17Z)
phase: pullrequest
findings: none
fixed: none
skipped: none
card: PR #38 summary (commentId: pr-body)
ci: run 33719556962 succeeded (apache-drain, nginx-drain, apache-whoami, nginx-whoami)
verdict: ready for review

## archive (2026-09-03T05:36:13Z)
phase: archive
findings: none
fixed: synced core_crs_sidecar_inspect-only to openspec/specs/; moved change to archive
skipped: none
card: PR #38 summary (commentId: pr-body)

## devdocsimpact (2026-09-03T05:36:13Z)
phase: devdocsimpact
findings: stale-usage Integration Key files (produced in implement)
fixed: knowledge/devdocs/build_testing_integration.md
skipped: none
card: PR #38 summary (commentId: pr-body)

## codereview (2026-09-03T05:36:13Z)
phase: codereview
findings: Performance judgement 16 MiB fixture
fixed: none
skipped: Performance 1 judgement
card: PR #38 summary (commentId: pr-body)

## implement (2026-09-03T05:33:53Z)
phase: implement
findings: local apache-drain and apache-whoami pins passed
fixed: Range success + Hostname; apache-whoami 416; drain 16MiB not-5xx
skipped: nginx-whoami Range (not measured)
card: PR #38 summary (commentId: pr-body)
localTests: passed
ci: run 33719316489 in progress

## propose (2026-09-03T05:31:21Z)
phase: propose
findings: FindSpecHost fold core_crs_sidecar_inspect-only
fixed: none
skipped: none
card: PR #38 summary (commentId: pr-body)
change: pin-inspect-only-range-large-body

## explore (2026-09-03T05:29:16Z)
phase: explore
findings: assumed Decisions on Range status, nginx 416, CRS 413 vs 200, whoami large-POST skip
fixed: none
skipped: none
card: PR #38 summary (commentId: pr-body)

## prepare (2026-09-03T05:27:07Z)
phase: prepare
findings: none
fixed: none
skipped: none
card: PR #38 summary (commentId: pr-body)
ci: run 33718842851 in progress
