---
name: /opsx-archive-document
id: opsx-archive-document
category: Workflow
description: Archive a completed change and, if documentation-worthy, add a summary to the knowledge base (no spec sync)
---

Archive a completed change in the experimental workflow. Same as `/opsx-archive` except: **no delta spec sync**; instead, **assess whether the change is documentation-worthy** and, if so, add a short summary to the project knowledge base using the knowledge-add-user workflow.

**Input**: Optionally specify a change name after the command (e.g. `/opsx-archive-document add-auth`). If omitted, check if it can be inferred from conversation context. If vague or ambiguous you MUST prompt for available changes.

**Steps**

1. **If no change name provided, prompt for selection**

   Run `openspec list --json` to get available changes. Use the **AskUserQuestion tool** to let the user select.

   Show only active changes (not already archived).
   Include the schema used for each change if available.

   **IMPORTANT**: Do NOT guess or auto-select a change. Always let the user choose.

2. **Check artifact completion status**

   Run `openspec status --change "<name>" --json` to check artifact completion.

   Parse the JSON to understand:
   - `schemaName`: The workflow being used
   - `artifacts`: List of artifacts with their status (`done` or other)

   **If any artifacts are not `done`:**
   - Display warning listing incomplete artifacts
   - Prompt user for confirmation to continue
   - Proceed if user confirms

3. **Check task completion status**

   Read the tasks file (typically `tasks.md`) for the change.

   Count tasks marked with `- [ ]` (incomplete) vs `- [x]` (complete).

   **If incomplete tasks found:**
   - Display warning showing count of incomplete tasks
   - Prompt user for confirmation to continue
   - Proceed if user confirms

   **If no tasks file exists:** Proceed without task-related warning.

4. **Assess documentation worthiness and optionally add to knowledge**

   Read the change artifacts: `proposal.md`, `design.md`, and `tasks.md` (and any specs if helpful).
   Also briefly scan the actual code/config changes to check whether the rationale is already captured there.

   **Default is: not worthy.** Only add to the knowledge base when the bar below is clearly met.

   **Documentation-worthy** — ALL of the following must be true:
   - The knowledge is **not already self-evident** from code, config comments, or naming (e.g. a `docker-compose.test.yml` comment that says "disable sanitizePath so absolute-form reaches plugin" is self-documenting — do not duplicate it).
   - It captures something that would **genuinely surprise or block** a future contributor who reads the code but not this change (e.g. a non-obvious platform behaviour, an ADR-style decision between two equally valid approaches, or a cross-cutting architectural constraint).
   - It has value **across multiple future changes**, not just for understanding this one fix.

   **Not documentation-worthy** — treat as such when any of the following apply:
   - The change is a **bugfix, one-liner, or small correction** with no lasting architectural impact.
   - New test helpers, test infra, or test config whose purpose is explained by **inline comments or naming** in the relevant files.
   - The entire rationale is already captured in **code comments, config comments, commit messages, or PR descriptions** — do not duplicate those into knowledge files.
   - A reader could understand *why* things are done by **reading the code for 2 minutes** without prior context.

   **If not documentation-worthy:**
   - State briefly: "Change assessed as not documentation-worthy (rationale is self-evident in code/config); skipping knowledge update."
   - Proceed to step 5.

   **If documentation-worthy:**
   - Summarize only the parts that are **not self-evident in code**: what cross-cutting decision was made, what non-obvious platform behavior applies, what gotcha will recur on future changes.
   - Do **not** copy full specs or proposal text; 2–4 bullets maximum.
   - Follow the **knowledge-add-user** workflow (read `.cursor/agents/knowledge-add-user.md`): build the architecture map from `openspec/knowledge/internal/` and `openspec/knowledge.user.md`, classify to the most specific applicable file, append a new section (with date), update `openspec/knowledge.user.md` if you created a new file.
   - Report where the knowledge was stored (file and section).

5. **Perform the archive**

   Create the archive directory if it doesn't exist:
   ```bash
   mkdir -p openspec/changes/archive
   ```

   Generate target name using current date: `YYYY-MM-DD-<change-name>`

   **Check if target already exists:**
   - If yes: Fail with error, suggest renaming existing archive or using a different date
   - If no: Move the change directory to archive

   ```bash
   mv openspec/changes/<name> openspec/changes/archive/YYYY-MM-DD-<name>
   ```

   (Use PowerShell-compatible move if on Windows: `Move-Item`.)

6. **Display summary**

   Show archive completion summary including:
   - Change name
   - Schema that was used
   - Archive location
   - Knowledge: "Added to <file> (section: …)" or "Not documentation-worthy; skipped"
   - Note about any warnings (incomplete artifacts/tasks)

**Output On Success (with knowledge added)**

```
## Archive Complete

**Change:** <change-name>
**Schema:** <schema-name>
**Archived to:** openspec/changes/archive/YYYY-MM-DD-<name>/
**Knowledge:** Added to openspec/knowledge/internal/<topic>.md (section: "<title>")

All artifacts complete. All tasks complete.
```

**Output On Success (not documentation-worthy)**

```
## Archive Complete

**Change:** <change-name>
**Schema:** <schema-name>
**Archived to:** openspec/changes/archive/YYYY-MM-DD-<name>/
**Knowledge:** Not documentation-worthy; skipped.

All artifacts complete. All tasks complete.
```

**Output On Error (archive exists)**

```
## Archive Failed

**Change:** <change-name>
**Target:** openspec/changes/archive/YYYY-MM-DD-<name>/

Target archive directory already exists.

**Options:**
1. Rename the existing archive
2. Delete the existing archive if it's a duplicate
3. Wait until a different date to archive
```

**Guardrails**
- Always prompt for change selection if not provided
- Use artifact graph (openspec status --json) for completion checking
- Don't block archive on warnings — inform and confirm
- Preserve .openspec.yaml when moving to archive (it moves with the directory)
- Do **not** sync delta specs to main specs in this command
- When adding knowledge: only include what is **not already self-evident in code or config**; never duplicate inline comments
- **Default is not worthy** — only add when a future contributor would genuinely be blocked without it
- If in doubt, skip; a lean knowledge base is more valuable than a noisy one
