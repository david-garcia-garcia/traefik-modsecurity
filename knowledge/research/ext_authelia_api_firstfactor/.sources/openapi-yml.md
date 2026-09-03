---
url: https://github.com/authelia/authelia/blob/master/api/openapi.yml
title: Authelia OpenAPI — POST /api/firstfactor
fetched: 2026-09-03
authority: official
---

Path `/api/firstfactor` documents `post` only (tags: Authentication; summary: Login).

Description: The firstfactor endpoint allows a user to login and generates an authentication cookie for authorization.

requestBody content: `application/json` schema `handlers.bodyFirstFactorRequest`.

Responses:
- `200` Successful Operation — `handlers.redirectResponse`
- `401` Unauthorized

No `405` response is listed on this operation. Passkey variants live under `/api/firstfactor/passkey` (GET start / POST complete) and are a different path.
