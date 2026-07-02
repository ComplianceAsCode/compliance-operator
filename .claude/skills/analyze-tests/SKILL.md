---
name: analyze-tests
description: Classify every Test* function in one or more Go test files by feature_group + operation_type, emit JSON, and produce a parallelization plan. Use to drive the testing-refactor effort described in testing-refactor.md.
---

# Analyze Tests

Distills a Go test file (or several) into structured rows, then proposes how to bucket them into parallel-runnable suites. Implements the workflow from `testing-refactor.md` § "Prompt" / "Parallel Suite Results" / "Parallelization Plan".

## Arguments

```
/analyze-tests <file>                # Analyze one file
/analyze-tests <file1> <file2> ...   # Analyze multiple files
/analyze-tests --all                 # All e2e files in tests/e2e/{parallel,serial,rosa}
/analyze-tests --plan                # Skip analysis; just plan from existing JSON in /tmp/test-analysis.json
```

The default targets:
```
tests/e2e/parallel/main_test.go
tests/e2e/serial/main_test.go
```

---

## Phase 1: Classify

Launch the **`test-analyzer`** subagent in parallel — one agent per file. Each agent reads its file and emits a JSON array per `.claude/agents/test-analyzer.md`.

**Important**: Launch all subagents in a single message so they run concurrently. Don't run them sequentially.

For each agent give it:

> Analyze the test file at `<path>` per `.claude/agents/test-analyzer.md`. Emit one JSON array per the schema. Do not add prose.

Collect each result and write the concatenated JSON to `/tmp/test-analysis.json` keyed by file:

```json
{
  "tests/e2e/parallel/main_test.go": [ { ... }, ... ],
  "tests/e2e/serial/main_test.go":   [ { ... }, ... ]
}
```

Show the user a short summary (per-file count, unique feature_groups, count by operation_type) so they can sanity-check before planning.

---

## Phase 2: Plan

Spawn **`test-suite-planner`** with the contents of `/tmp/test-analysis.json` and any layout context (`ls tests/e2e/`).

Have it produce the plan per `.claude/agents/test-suite-planner.md` § Output:
1. Suite inventory table
2. Per-suite test list
3. Shared plumbing
4. Migration order
5. Risks & open questions

Present the plan to the user. Stop here — do not start splitting files until the user approves.

---

## Phase 3 (optional): Execute

If the user approves and wants to start the migration, point them at the `/split-test-file` skill. That skill takes a single feature_group and performs the mechanical extraction.

Do not auto-execute the full migration in one shot. Move one feature_group at a time, run the tests after each, then proceed.
