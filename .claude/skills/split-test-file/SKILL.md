---
name: split-test-file
description: Mechanically extract a feature_group's tests out of tests/e2e/parallel/main_test.go (or serial/main_test.go) into a new tests/e2e/{parallel|serial}/<group>_test.go file. Use one feature_group at a time after the user approves the plan from /analyze-tests.
---

# Split Test File

Takes a feature_group (e.g. `profile_parsing`) plus the test-suite-planner output, and physically moves those tests from the monolithic `main_test.go` into a new per-feature file. Preserves package name, `t.Parallel()` calls, helper references, and import order.

## Arguments

```
/split-test-file <feature_group> [--package parallel|serial] [--dry-run]
```

If `--package` isn't given, infer from the planner output (default: `parallel`).

`--dry-run` shows the diff plan without writing files.

---

## Preconditions

1. `/analyze-tests` has been run and `/tmp/test-analysis.json` exists.
2. The user has approved the plan from `test-suite-planner`.
3. The working tree for `tests/e2e/` is clean (`git status tests/e2e/`).

Abort with a clear error if any precondition fails. Don't auto-fix tree dirtiness.

---

## Workflow

### 0. Cost-aware preflight

Before any move, run `/test-runtime --top 40` and grep for the tests in your feature group. Print a one-line summary of the cumulative wall-time being relocated:

```
Migrating <N> tests, cumulative wall-time ~Xs (mean across recent runs).
Slowest test in group: TestName at Ys/run.
```

This is purely informational, but it's the single most useful "what am I about to do" check before a split. If the group includes a multi-hundred-second test, you want to know.

### 1. Identify the test set

From `/tmp/test-analysis.json` plus the planner's suite inventory, list the exact `Test*` names that belong in the new file. Confirm with the user before touching anything.

### 2. Locate source spans

For each Test in the set, find its line range in `tests/e2e/{parallel|serial}/main_test.go`:

```bash
grep -n "^func Test" tests/e2e/parallel/main_test.go
```

Identify the start line and the next `^func ` (or EOF) to bound each test. Include any test-local `func` helpers immediately above/below if they're only called by tests in this set — verify with a grep across the rest of the file.

### 3. Create the new file

Path: `tests/e2e/<package>/<feature_group>_test.go` (snake_case).

Header structure:
```go
package <package>_e2e

import (
    // exact subset of imports needed by the moved tests
)

// moved tests go here
```

For the import list:
- Start with the full import block from `main_test.go`.
- Remove imports not referenced by any moved test.
- Run `gofmt -s -w` after writing — let the formatter sort/group.

### 4. Remove the moved code from main_test.go

Delete the moved function bodies (and any helpers you moved). Do not delete `TestMain`, package-level vars (`brokenContentImagePath`, `contentImagePath`), or shared helpers used by remaining tests.

### 5. Verify

Compile both files:
```bash
go build ./tests/e2e/<package>/...
```

If the build fails because an import is now unused in `main_test.go`, run `goimports -w tests/e2e/<package>/main_test.go`. If a helper was used by both moved and remaining tests, restore it in `main_test.go` (it stays shared until a follow-up promotes it to `framework/`).

### 6. Run one moved test

Pick one test from the moved set:
```bash
make e2e-parallel E2E_GO_TEST_FLAGS="-v -timeout 45m -run ^<TestName>$"
```

(or `e2e-serial`). If green, hand off to `test-verifier` for a deeper read. Don't claim success on `go test` alone.

### 7. Report

```markdown
## Split complete: <feature_group>

- **Moved**: N tests (list)
- **New file**: tests/e2e/<package>/<feature_group>_test.go (LOC: X)
- **main_test.go remaining**: Y tests, Z lines
- **Sample run**: ✅ TestName passed in Ns
- **Next**: <next feature_group from planner output>
```

---

## Discipline

- **One feature_group per invocation.** Don't bundle multiple groups.
- **No semantic changes.** This skill is mechanical — if a test needs refactoring, that's a separate task. Move first; refactor later.
- **Preserve `t.Parallel()`** exactly. Don't add it to a `serial_e2e` file. Don't remove it from a `parallel_e2e` move.
- **Don't promote helpers to `framework/`** in this skill. If a helper is now shared across multiple files, leave it in `main_test.go` and flag it for a follow-up.
