# Deviations

- [x] taken  dest `main` instead of the ask's `master`
  Asked: target branch is `master`.
  Instead: dest is `origin/main` (`origin/HEAD`); no `origin/master`.
  Owner: `devstate/2026/09/2026-09-16-zzz-test-prefix/handoff.yaml` `destBranch`
  Why: honouring `master` cannot fetch; the long-lived branch that already has the product tests is `main`.
  By: prepare
  Requester: not asked
