---
name: /knowledge-research
id: knowledge-research
category: Knowledge
description: Research a topic for this project. Checks local knowledge first, then searches the internet. Adds useful sources to the knowledge base and fetches their content. Also accepts user-provided knowledge directly.
---

Read the agent instructions at `.cursor/agents/knowledge-research.md` and follow them exactly.

The argument(s) passed to this command are the topic, question, or knowledge to act on. Examples:
- `/knowledge-research how does Traefik load plugins` → SEARCH mode
- `/knowledge-research add: the WAF returns 200 for allowed requests` → ADD mode
- `/knowledge-research convert traefik-plugin-demo to internal` → CONVERT mode

If no mode keyword is provided, infer the mode from the content.
