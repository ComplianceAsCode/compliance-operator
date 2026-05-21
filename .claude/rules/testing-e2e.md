---
paths:
  - "tests/e2e/**"
---

# E2E Testing Rules — Compliance Operator

Applies to everything under `tests/e2e/`.

## File placement

- **Parallel-safe**: scan-only or validation tests → `tests/e2e/parallel/<feature_group>_test.go`.
- **Mutating / disruptive**: applies remediations, taints nodes, modifies cluster config, restarts operator → `tests/e2e/serial/<feature_group>_test.go`.
- **ROSA-specific**: `tests/e2e/rosa/`.
- **Never add new tests to `main_test.go`** — that file is being shrunk. Its remaining role is `TestMain` + helpers local to the package.

`<feature_group>` matches the canonical set in `.claude/agents/test-analyzer.md` (e.g. `scan_configuration`, `profile_parsing`, `custom_rules`, `remediation`, `validation`, `metrics`, `profile_tailoring`).

## Per-test rules

- Place `t.Parallel()` as the first statement of every test in the `parallel_e2e` package. Never in `serial_e2e`.
- Resource names: `name := getObjNameFromTest(t)`. Don't hard-code names that could collide with another concurrent test.
- Namespace: `framework.Global.OperatorNamespace`. Don't create a new namespace per test unless the test specifically validates namespace-level behavior.
- Every `f.Client.Create(...)` takes `getCleanupOpts(ctx)`. Without it, the resource leaks into the next test.
- No `time.Sleep`. Use `wait.PollImmediate` or the framework's `waitFor*` helpers.

## Framework usage

- Always use `framework.Global`. Never construct a second `Framework`.
- Before writing a new `waitFor...` or `assertHas...` helper, grep `tests/e2e/framework/common.go` and `utils.go` — chances are it exists.
- New helpers go in `framework/common.go` (assertions) or `framework/utils.go` (low-level). Don't put helpers in a `_test.go` file unless they're truly local.

## Content images

- Tests rely on `CONTENT_IMAGE` and `BROKEN_CONTENT_IMAGE` env vars set by the Makefile. Tests reference them via `contentImagePath` / `brokenContentImagePath` package-level vars.
- If your test needs a different content image, add a fixture under `tests/data/` and document the regeneration step (see `make cel-bundle`).

## Result assertion patterns

- For "scan should succeed and be compliant", use `waitForSuiteScansStatus(t, f, ns, name, PhaseDone, ResultCompliant)`.
- For a specific check, use `assertHasCheck(f, suiteName, scanName, expectedCheckResult)`.
- For warnings on the suite, use `getEventsForObject` / `assertEventContains`.

## Anti-patterns

- Tests that pass when the operator isn't running (no oc/k8s call ever exercised).
- Tests that rely on test execution order — every test must set up its own preconditions.
- Tests that taint or untaint nodes outside `serial`.
- Tests that apply a remediation in `parallel`.

## Running

```
make e2e-parallel E2E_GO_TEST_FLAGS="-v -timeout 45m -run ^TestName$"
make e2e-serial   E2E_GO_TEST_FLAGS="-v -timeout 60m -run ^TestName$"
```

Always run a single test before pushing — `make e2e` is a long, expensive feedback loop.
