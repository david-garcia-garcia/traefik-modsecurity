# Remove dummy CRS origin from tests and documentation

Caller: chat (`/sbs-dev-workflow`, slug `remove-dummy`). Dedicated worktree required.

## Spec

We have issues related to the sidecar dummy backend returning codes that are not 200 OK (Range, and sidecar 3xx including 304 Not Modified treated as a security block — `opus_review.md` finding 4, `pkg/modsecurity/serve.go` block predicate `>= 300 && < 500`).

Question: are we confident that the new deployment strategy, where nginx and Apache CRS use a drain configuration so that no dummy backend is required, is robust enough that we can completely remove from tests and documentation the usage of this dummy backend?

If there is enough confidence (improve integration tests if needed), then simplify tests and documentation to only focus on the drain setup, ensure nothing mentions the old dummy backend, and ensure README.md correctly tells users how to configure their Apache and nginx CRS (link to sample config files already used in tests).

## Related

- opus_review.md:66-80 — sidecar 3xx including 304 treated as block
- Drain overlays already on main: `crs-apache/httpd-vhosts.drain.conf`, `crs-nginx/drain-origin.conf`
- Demo compose already drain; test whoami stacks still run unlabeled `dummy`
