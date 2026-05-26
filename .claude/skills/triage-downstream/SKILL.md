---
name: triage-downstream
description: Investigate NOTE(rhmdnd) markers in the downstream OpenShift QE compliance-operator test file, map each downstream test to upstream coverage, and produce Jira story drafts in the format used in testing-refactor.md.
---

# Triage Downstream

Implements the workflow described in `testing-refactor.md` § "Jira Prompting" / "Jira Notes" / "Jira Stories".

## Arguments

```
/triage-downstream <path-to-downstream-test-file>
/triage-downstream <path> --id <TestID>           # Focus on one test
/triage-downstream <path> --output <jira.md>      # Write Jira drafts to file
```

The downstream file is typically:
```
<openshift-tests-private>/test/extended/securityandcompliance/compliance_operator.go
<openshift-tests-private>/test/extended/securityandcompliance/compliance_operator_serial_test.go
```

You will receive the absolute path from the user — this repo doesn't contain it.

---

## Workflow

### 1. Sanity-check input

Confirm the file exists and contains `NOTE(rhmdnd)`. If not, report and exit.

```bash
grep -c 'NOTE(rhmdnd)' <path>
```

### 2. Spawn downstream-test-triager

Hand off the path (and optional `--id`) to the **`downstream-test-triager`** subagent. Let it produce the report per `.claude/agents/downstream-test-triager.md`.

For each NOTE marker the agent will:
- Read the surrounding It/g.It block.
- Search upstream for the referenced test.
- Categorize as `UPSTREAM_DUPLICATE` / `UPSTREAM_PARTIAL` / `UPSTREAM_MISSING` / `NEEDS_DISCUSSION`.
- Draft the Jira body in the existing format.

### 3. Present and persist

Show the user the summary table. If `--output` was passed, write all Jira drafts to that file (or `/tmp/co-jira-drafts.md` by default).

### 4. Next step

Ask the user which entries to act on:
- **UPSTREAM_DUPLICATE**: maintainer files a Downstream Cleanup Jira; no upstream code change.
- **UPSTREAM_PARTIAL**: route to `/add-e2e-test` to enhance the upstream analogue (or to `e2e-test-writer` directly).
- **UPSTREAM_MISSING**: route to `/add-e2e-test` to write a fresh upstream test.
- **NEEDS_DISCUSSION**: leave the Jira in draft and flag to the user.

Don't open Jiras automatically — leave that to the maintainer. The user has the `jira-cli` skill if they want to file directly.

---

## Discipline

- Don't modify the downstream file.
- Don't propose to upstream a test without grepping `tests/e2e/parallel/` and `tests/e2e/serial/` first.
- Preserve each NOTE body verbatim in the Jira draft — it's the historical record.
