# Knowledge

Tracks project documentation, architecture notes, design decisions, and learned experiences.
All files here are committed to git under `openspec/knowledge/internal/`.

> **Agents:** Read relevant entries before designing or implementing features. All files are locally available — no download needed.

---

## Format Reference

```
- **<Component Title>**
  - local: knowledge/internal/<component>.md
  - description: <one-line summary of what this covers>
```

Knowledge is stored as `.md` files under `openspec/knowledge/internal/`, in whatever hierarchy the project builds up over time. The structure is user-defined — it may be flat, nested, or a mix.

**Examples of possible structures:**
```
knowledge/internal/middleware-design.md        ← flat file
knowledge/internal/plugin/lifecycle.md         ← subfolder for a richer area
knowledge/internal/waf-proxy/body-handling.md  ← nested topic
```

The `local` field is a direct path to the file (not a folder).

---

## Sources

- **Integration Test Conventions**
  - local: knowledge/internal/testing-conventions.md
  - description: Rules for writing Pester integration tests — use existing helpers, keep It blocks linear, extract complexity to TestHelpers.ps1.

- **Middleware Design Knowledge**
  - local: knowledge/internal/middleware-design.md
  - description: Traefik middleware lifecycle — one instance per route, blocking init, when and how to use global shared state.
