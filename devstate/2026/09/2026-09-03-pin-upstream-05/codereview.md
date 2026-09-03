# Code review
pin: origin/main (2f39486)
command: git diff origin/main...HEAD -- . ':!devstate' ':!.cursor'
head: (after apply) reuse startTestBlockingWAF

## Standards
1. [hard] Consume before produce — `pkg/modsecurity/upstream_issue_05_test.go:165` and `:208` — abort tests copied a blocking sidecar next to `startTestBlockingWAF` in `serve_test.go`
   → Call `startTestBlockingWAF` (applied)

## Spec
none

Requirements walked:
- Handshake detection does not panic — `TestPlugin_UpstreamIssue05_IsWebsocketDoesNotPanic`, `TestPlugin_UpstreamIssue05_ReporterFontGETDoesNotPanic`
- Inbound abort does not nil-deref — `TestPlugin_UpstreamIssue05_InboundCancelDoesNotNilDeref`, `TestPlugin_UpstreamIssue05_HTTP2ClientAbortIsNotNilDeref`

## Security
none

`InsecureSkipVerify` is test-only against local `httptest` TLS for HTTP/2. Not a product sink.

## Performance
none

Abort waits are bounded by `t.Fatal` timeouts. No growing production path.

## Applied
- Standards 1: cancel and HTTP/2 tests now call `startTestBlockingWAF`

## Recorded and skipped
none.

Standards: 1 finding, worst: Consume before produce at `upstream_issue_05_test.go` (applied)
Spec: 0 findings, worst: none
Security: 0 findings, worst: none
Performance: 0 findings, worst: none
