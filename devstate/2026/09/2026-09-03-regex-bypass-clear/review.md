# Review journal

## prepare (2026-09-03)
phase: prepare
findings: none
fixed: none
skipped: auto-anchor of pathRegexp (human: operator writes ^)

## explore (2026-09-03)
phase: explore
findings: unanchored MatchString reproduced; `/health` matches `/healthz` and `/index.php/health`; Go Path is not slash-normalized
fixed: none
skipped: auto-anchor; matcher/RawPath guard

## propose (2026-09-03)
phase: propose
findings: fold core_plugin_middleware_bypass-rules
fixed: none
skipped: auto-anchor

## implement (2026-09-03)
phase: implement
findings: none
fixed: README examples, BypassRule comment, pinning tests
skipped: auto-anchor; RawPath guard

## codereview (2026-09-03)
phase: codereview
findings: none
fixed: none
skipped: none

## devdocsimpact (2026-09-03)
phase: devdocsimpact
findings: stale-usage on core_plugin_middleware How-to
fixed: operator-owned anchors and Path not slash-normalized on that packet
skipped: none

## archive (2026-09-03)
phase: archive
findings: none
fixed: folded ADDED requirements into core_plugin_middleware_bypass-rules; moved change to archive/2026-09-03-bypass-pathregexp-docs
skipped: none

## pullrequest (2026-09-03)
phase: pullrequest
findings: none
fixed: title dropped WIP; CI succeeded
skipped: none
