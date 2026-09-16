---
url: file:///d:/repositories/wt-modsec-2026-09-16-import-middleware-utilities/pkg/reclaim/default.go
title: local pkg/reclaim/default.go
fetched: 2026-09-16
authority: source
ref: worktree@2026-09-16:pkg/reclaim/default.go
---

func Default() *Table
func Open(ctx context.Context, key string, logger *slog.Logger, create func() (any, error)) (any, error)
func Reset()
func ResetWith(grace time.Duration)

Open returns Default().Open(...). Reset calls ResetWith(DefaultGrace). ResetWith replaces defaultTable after defaultTable.Reset().

Local table.go: NewTable(grace time.Duration) *Table; (*Table) Open without Hooks; value Close() via closer interface.
