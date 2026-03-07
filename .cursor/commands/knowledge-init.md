---
name: /knowledge-init
id: knowledge-init
category: Knowledge
description: Initialize or refresh the knowledge base. Reads knowledge.external.md, finds external sources whose local folder is missing, and downloads them. Run after cloning the repo or after adding new entries to knowledge.external.md.
---

Read the agent instructions at `.cursor/agents/knowledge-init.md` and follow them exactly.

Any arguments passed to this command (e.g. a specific source title) should be used to scope which entries to process. If no arguments are given, process all missing entries.
