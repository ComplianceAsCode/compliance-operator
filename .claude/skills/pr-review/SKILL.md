---
name: pr-review
description: Submit inline review comments on a GitHub PR for the Compliance Operator using the gh CLI. Use after the code-reviewer agent has produced findings and you want to post them to the PR.
---

# PR Review

Posts the findings from `code-reviewer` (or any review pass) to a GitHub PR as inline comments, using the existing `gh` CLI.

## Arguments

```
/pr-review <pr-number>             # Auto-detect owner/repo from current dir
/pr-review <owner>/<repo>#<num>    # Explicit
/pr-review <url>                   # From a PR URL
```

The PR must be open and the user must have write access to the repo.

---

## Workflow

### 1. Gather findings

Source of findings (in priority order):

- A path to a markdown file (e.g. `/tmp/co-review.md`) the user provides.
- A recent `code-reviewer` agent output in this conversation.

Findings should each have: `path`, `line`, `body`, optionally a `suggestion` block.

### 2. Build the review JSON

Write to `/tmp/pr-review-comments.json`:

```json
{
  "body": "Overall review summary",
  "event": "COMMENT",
  "comments": [
    {
      "path": "pkg/controller/compliancescan/compliancescan_controller.go",
      "line": 124,
      "body": "Status update should use r.Status().Update(). Otherwise the spec subresource gets touched and we lose the optimistic-concurrency guarantee on status.\n\n```suggestion\n    if err := r.Status().Update(ctx, scan); err != nil {\n```\n\nEvidence: `.claude/rules/controller.md` § Status conventions"
    }
  ]
}
```

`event` is one of `COMMENT` / `APPROVE` / `REQUEST_CHANGES`. Default to `COMMENT`. Only use `APPROVE` if the user explicitly approves.

### 3. Confirm before posting

Show the user the JSON (especially the count + first 2 comments) and ask for confirmation. Don't post without explicit go-ahead — review comments are visible to maintainers and not trivially deletable.

### 4. Submit

```bash
gh api -X POST repos/<owner>/<repo>/pulls/<num>/reviews --input /tmp/pr-review-comments.json
```

Capture the returned review URL and show it to the user.

---

## Replying / Resolving

For replying to existing threads and resolving them, use the GraphQL flow from toolhive's skill — `gh api graphql ...`. Do not resolve a thread without user approval; resolving is irreversible from Claude's side without manual intervention.

---

## Discipline

- **Never post without user confirmation.** A PR comment is public.
- **One review per call.** Don't batch multiple PRs' reviews together.
- **Don't `APPROVE`** unless the user said so in plain words.
- **Don't bypass `.claude/rules/`** when reviewing — they're the project's stated conventions and the reviewer should cite them.
