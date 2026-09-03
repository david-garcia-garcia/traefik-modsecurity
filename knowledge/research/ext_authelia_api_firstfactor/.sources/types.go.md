---
url: https://github.com/authelia/authelia/blob/v4.39.20/internal/handlers/types.go
title: bodyFirstFactorRequest
fetched: 2026-09-03
authority: source
ref: authelia/authelia@v4.39.20:internal/handlers/types.go
---

bodyFirstFactorRequest is the JSON body received by the first-factor endpoint.

Required JSON fields: `username`, `password`.

Optional: `targetURL`, `requestMethod`, `keepMeLoggedIn`, `flowID`, `flow`, `subflow` (`json:"subflow"`), `userCode`.

redirectResponse (success payload when a redirection URL was provided) has `redirect`.
