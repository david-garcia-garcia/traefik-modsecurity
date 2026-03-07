---
name: /knowledge-add-external
id: knowledge-add-external
category: Knowledge
description: Add a single external knowledge source. Repositories are shallow-cloned as-is (no scan). Articles are fetched, synthesized to compact markdown, and security-reviewed. Registers the source in knowledge.external.md and notifies the user.
---

Read the agent instructions at `.cursor/agents/knowledge-add-external.md` and follow them exactly.

Parse the arguments passed to this command to extract the source details:

**Repository example:**
`/knowledge-add-external https://github.com/traefik/traefik tag v3.6.9`
`/knowledge-add-external https://github.com/traefik/traefik branch master`
→ type: repository, url: the GitHub URL, branch/tag: the ref provided (default: main if omitted)

**Article example:**
`/knowledge-add-external https://doc.traefik.io/traefik/plugins/`
→ type: article, url: the URL

**Derive automatically from the input:**
- title: a descriptive human-readable name based on the repo/page
- local path: kebab-case subfolder under `knowledge/external/` derived from the org/repo or domain/topic
- description: one-line summary of why this is relevant to the project

If any required detail is ambiguous, ask before proceeding.
