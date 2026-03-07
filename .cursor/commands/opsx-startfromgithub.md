---
name: /opsx-startfromgithub
id: opsx-startfromgithub
category: Workflow
description: Start an OpenSpec change from a GitHub issue or pull request. Reads the content and comments, creates a branch, and runs the OpenSpec propose workflow using that content as the change description.
---

Start an OpenSpec change from a GitHub issue or pull request.

**Input**: Optionally a number or URL. Examples:
- `/opsx-startfromgithub 33`
- `/opsx-startfromgithub https://github.com/owner/repo/issues/33`
- `/opsx-startfromgithub https://github.com/owner/repo/pull/47`

---

## Steps

### 1. Parse the input

If a URL is given, extract the number and detect whether it is an issue (`/issues/`) or a pull request (`/pull/`).

If only a number is given (no URL), use the **AskUserQuestion tool** to ask:
> "Is #<N> an issue or a pull request?"
> - Issue
> - Pull request

If no argument is given at all, ask:
> "What GitHub issue or pull request do you want to work on? Provide the number or URL."
> Then ask issue vs. PR if needed.

### 2. Resolve the repository

Read `openspec/project.md` to find:
- The main/default branch (`Main branch` field; fallback: `master`)
- The GitHub owner and repo (`Owner` and `Repo` fields)

If owner/repo are not in `project.md`, parse them from `git remote -v` (prefer `origin`).

### 3. Ask the user how to start the branch

Use the **AskUserQuestion tool**:

> "How do you want to start this branch?"
> - **From current state** — create the branch directly from wherever HEAD is now
> - **From default branch** — switch to `<main-branch>`, pull latest, then branch

If **From current state**:
- Run `git status --porcelain`
- If dirty: warn the user and ask if they want to continue anyway or stop to clean up
- Proceed from current HEAD

If **From default branch**:
- Run `git status --porcelain`
- If dirty: **stop** — uncommitted changes must be stashed or committed before switching branches
- Run:
  ```bash
  git checkout <main-branch>
  git pull
  ```
- If either fails: stop and report the error

### 4. Determine the branch name

**For an issue**: base name `github-<N>` (e.g. `github-33`)  
**For a PR**: base name `github-pr-<N>` (e.g. `github-pr-47`)

Check whether the name is taken locally or remotely:
```bash
git branch --list <base-name>
git branch -r --list origin/<base-name>
```

If taken, append a letter suffix in order: `github-33a`, `github-33b`, etc. Use the first available name.

### 5. Create the branch

```bash
git checkout -b <branch-name>
```

Report the branch name. Do **not** push and do **not** create a PR.

### 6. Read the GitHub content in full

#### If source is an **issue**

Using the `issue_read` MCP tool:
- `method: get` — title, body, labels, assignees
- `method: get_comments` — all comments (perPage: 100, paginate if needed)

Synthesize:
```
Issue #<N>: <title>

<issue body>

--- Comments ---
[<author>]: <comment body>
...
```

#### If source is a **pull request**

Using the `pull_request_read` MCP tool:
- `method: get` — title, body, head/base branch, author
- `method: get_comments` — general PR comments (perPage: 100, paginate if needed)
- `method: get_review_comments` — inline review comments (perPage: 100, paginate if needed)
- `method: get_reviews` — review decisions and summaries

Synthesize:
```
Pull Request #<N>: <title>
Author: <author>  |  <head-branch> → <base-branch>

<PR body>

--- Review Comments ---
[<author> on <file>:<line>]: <comment>
...

--- General Comments ---
[<author>]: <comment>
...

--- Reviews ---
[<reviewer>] <APPROVED|CHANGES_REQUESTED|COMMENTED>: <body>
...
```

### 7. Derive the OpenSpec change name

From the title, derive a kebab-case change name:
- Lowercase, strip special characters, replace spaces with hyphens
- For issues: prefix `issue-<N>-<short-title>`
- For PRs: prefix `pr-<N>-<short-title>`
- Examples: `issue-33-add-retry-logic`, `pr-47-fix-body-size-413`
- Keep under 40 characters

### 8. Hand off to the propose workflow

Read and follow the instructions in `.cursor/commands/opsx-propose.md` exactly, as if the user had typed `/opsx-propose <change-name>`.

Pass the derived `<change-name>` as the input so the propose command does not need to ask for it. Use the synthesized issue/PR content (from Step 6) as the primary source of requirements when writing `proposal.md` — treat it as the user's description of what to build.

### 9. Report

```
## Ready to implement

Source:   <Issue|PR> #<N> — <title>
Branch:   <branch-name>  (local only — push when ready)
Change:   openspec/changes/<change-name>/

Artifacts created:
  ✓ proposal.md
  ✓ design.md
  ✓ tasks.md

Run `/opsx-apply` to start implementing.
```

---

## Rules

- **Always ask** issue vs. PR if not obvious from the URL
- **Always ask** how to start the branch — never assume
- **Never push** the branch automatically
- **Never create a PR** — leave that to the user
- **Dirty working tree blocks a branch switch** — but not "start from current state" (warn only)
- **Use the GitHub content as the source of requirements** — don't invent scope
- **Derive the change name from the title** — don't ask the user to name it
- **If the OpenSpec CLI is not available**: stop after creating the branch, tell the user to install it (`npm install -g @fission-ai/openspec@latest`), then re-run
- If `openspec new change` fails because the change already exists: ask whether to continue it or create a new one with a different name
