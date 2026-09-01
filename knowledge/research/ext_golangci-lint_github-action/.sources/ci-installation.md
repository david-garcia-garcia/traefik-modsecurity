---
url: https://golangci-lint.run/docs/welcome/install/ci/
title: CI Installation
fetched: 2026-09-01
authority: official
---

Reproducible CI: do not fail all builds at once. That happens if `linters.default: all` and a new linter is added, or when an upstream linter is upgraded even without `all`.

Highly recommended: install a **specific** golangci-lint version from the releases page.

GitHub Actions: use the official GitHub Action. Faster than a plain binary install because of caching. Creates GitHub annotations for found issues.
