# Authelia first-factor login API

Authelia's portal login submits **POST `/api/firstfactor`**. Official OpenAPI documents **200** (success) and **401** (unauthorized). It does **not** document **405** as a first-factor success or failure. A 405 on that path is Method Not Allowed from some other hop (sidecar, nginx `limit_except`, wrong verb), not Authelia's documented login reply.

## Path and method

The OpenAPI path is `/api/firstfactor` with **post** only. Summary: "Login". Description: the firstfactor endpoint allows a user to login and generates an authentication cookie for authorization.

Owner: [authelia/authelia `api/openapi.yml`](https://github.com/authelia/authelia/blob/master/api/openapi.yml) (`/api/firstfactor` `post`).

Extract: `.sources/openapi-yml.md`

## Request body

Official request content type is `application/json` with schema `handlers.bodyFirstFactorRequest`. Source type requires `username` and `password`. Optional fields include `targetURL`, `requestMethod`, `keepMeLoggedIn`, `flowID`, `flow`, `subflow`, `userCode`.

Owner: [authelia/authelia `internal/handlers/types.go`](https://github.com/authelia/authelia/blob/v4.39.20/internal/handlers/types.go) (`bodyFirstFactorRequest`). Same schema ref on the OpenAPI file above.

Extract: `.sources/types.go.md`

This plugin's issue-13 unit test uses a form-urlencoded fixture (`username=alice&password=secret`) as a typical login POST body. That is a plugin test shape, not Authelia's JSON contract. Authelia is not in this repo's compose.

## Documented statuses

OpenAPI responses for POST `/api/firstfactor`:

| Status | Meaning |
| --- | --- |
| 200 | Successful Operation (`handlers.redirectResponse`) |
| 401 | Unauthorized |

No 405 appears on that operation. Authelia "wrong password" is 401, not 405. The SPA can still paint "incorrect username/password" when the POST fails for any reason (including a copied sidecar 405).

Owner: [authelia/authelia `api/openapi.yml`](https://github.com/authelia/authelia/blob/master/api/openapi.yml).

Extract: `.sources/openapi-yml.md`

## Implication for this plugin

This product does not implement Authelia. A unit test that posts to `/api/firstfactor` with portal Host and Traefik identity headers checks that **this plugin** does not invent 405. If the sidecar allows, `next` runs. If the sidecar returns 405, that status is copied as a security block.
