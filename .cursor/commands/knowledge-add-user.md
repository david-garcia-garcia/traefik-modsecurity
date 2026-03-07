---
name: /knowledge-add-user
id: knowledge-add-user
category: Knowledge
description: Add user-provided knowledge to the project knowledge base. Accepts facts, decisions, architecture notes, domain knowledge, and learned experiences. Automatically classifies them into the right component/subcomponent of the system.
---

Read the agent instructions at `.cursor/agents/knowledge-add-user.md` and follow them exactly.

The argument(s) passed to this command are the knowledge to store. This can be:
- A fact, decision, or observation: `/knowledge-add-user the WAF returns 403 with an HTML body when blocking`
- A longer explanation typed after the command
- A request to document something: `/knowledge-add-user document how body size limiting works`

Follow the full classification workflow from the agent: build the architecture map, classify to the most specific component, ask if uncertain, write the knowledge, update knowledge.user.md, and always report where it was stored and why.
