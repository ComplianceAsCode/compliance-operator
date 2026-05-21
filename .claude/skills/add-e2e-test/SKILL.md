---
name: add-e2e-test
description: Guided creation of a new e2e test in the right package and file. Use when adding upstream coverage, upstreaming a downstream test, or writing a regression test for a fix.
---

# Add E2E Test

Walks through writing a single new e2e test end-to-end: pick the right feature_group, the right package (parallel vs serial), the right helpers; write the test; run it once; hand off to test-verifier.

## Arguments

```
/add-e2e-test "<short description>"
```

Example: `/add-e2e-test "platform scan launched from a ComplianceScan CR (not SSB) succeeds"`.

---

## Phase 1: Classify the new test

Ask the user (via AskUserQuestion if any is ambiguous):

1. **feature_group**: which canonical group does this fit? (`Profile Parsing` / `Profile Tailoring` / `Custom Rules` / `Scan Configuration` / `Scheduled Suite` / `Remediation` / `Metrics` / `Validation` / `Operator Configuration` / `Storage` / `Hypershift` / `Logging` / `File Integrity`)
2. **operation_type**: does the test apply a remediation, taint a node, or modify cluster-global state? → `serial`. Otherwise → `parallel`.
3. **Closest analogue**: which existing test should I model this on?

If the user supplies a downstream test name, run the `downstream-test-triager` first to confirm there isn't already upstream coverage.

---

## Phase 2: Spawn e2e-test-writer

Hand off to the **`e2e-test-writer`** subagent with:

- The classification (group + package).
- Path of the target file: `tests/e2e/<package>/<feature_group>_test.go`. If the file doesn't exist yet, the writer creates it.
- Path of the closest analogue to model the new test on.
- A clear statement of what the test must assert.

Wait for the writer to produce the new function.

---

## Phase 3: Compile & run once

```bash
go build ./tests/e2e/<package>/...
make e2e-<package> E2E_GO_TEST_FLAGS="-v -timeout 45m -run ^<TestName>$"
```

If compile fails, route back to the writer with the error. If runtime fails, route to `test-verifier` for diagnosis.

---

## Phase 4: Verify

Spawn **`test-verifier`** to run the new test and produce a verdict per `.claude/agents/test-verifier.md`.

If verdict is `PASS`, present the diff and the verifier report to the user.
If `FAIL` or `INCONCLUSIVE`, surface the verifier's diagnosis and ask the user how to proceed.

---

## Discipline

- Don't write the test in the wrong package "just to see it compile". If unsure, ask.
- Don't model on a test that uses a deprecated pattern (e.g. `defer ctx.Cleanup()` was the v1; new tests use `getCleanupOpts`). If the analogue is old, normalize while writing.
- Don't add a `t.Skip` for "not yet implemented" — write the test against the behavior you expect; if it fails, that's a real result.
