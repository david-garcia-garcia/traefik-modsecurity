---
url: https://go.dev/src/net/http/client.go
title: net/http Client.deadline
fetched: 2026-09-01
authority: source
ref: go.dev/src/net/http/client.go
---

func (c *Client) deadline() time.Time {
	if c.Timeout > 0 {
		return time.Now().Add(c.Timeout)
	}
	return time.Time{}
}

setRequestCancel: if deadline.IsZero() { return nop, alwaysFalse }
