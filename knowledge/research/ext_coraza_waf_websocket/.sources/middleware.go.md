---
url: https://github.com/corazawaf/coraza/blob/5c9a34ab5b860479f18fa237bea7a05c6c3f9d93/http/middleware.go
title: Coraza http.WrapHandler
fetched: 2026-09-03
authority: source
ref: corazawaf/coraza@5c9a34ab5b860479f18fa237bea7a05c6c3f9d93:http/middleware.go
---

processRequest fills transaction variables from http.Request: ProcessConnection, ProcessURI, AddRequestHeader (including Host and Transfer-Encoding), ProcessRequestHeaders, optional request body, ProcessRequestBody. Stops on interruption.

WrapHandler: if IsRuleEngineOff(), call next handler unwrapped. Else processRequest; on interruption WriteHeader(deny status) and return. Else wrap ResponseWriter, call next, then processResponse.

Upgrade headers are not a skip condition.
