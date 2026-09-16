---
url: https://github.com/david-garcia-garcia/traefik-middleware-utilities/blob/v1.0.3/reclaim/table.go
title: reclaim/table.go excerpts
fetched: 2026-09-16
authority: source
ref: github.com/david-garcia-garcia/traefik-middleware-utilities@950b08de:reclaim/table.go
---

type Hooks struct {
	Sleep func()
	Wake  func()
	Close func()
	EnforceCloseBeforeOpen bool
}

type Config struct {
	Grace time.Duration
}

func New(cfg Config) *Table { /* negative Grace → DefaultGrace */ }

func (t *Table) Open(ctx context.Context, key string, logger *slog.Logger, create func() (any, error), hooks Hooks) (any, error)

func (t *Table) OpenWithHooks(ctx context.Context, key string, logger *slog.Logger, create func() (any, Hooks, error)) (any, error)

// Reset ends every incarnation on this table. … Tests only …
func (t *Table) Reset()

// create takes no arguments: Yaegi cannot call func(context.Context) (any, error).
