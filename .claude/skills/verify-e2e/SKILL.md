---
name: verify-e2e
description: Run a single Compliance Operator e2e test against the current cluster and produce a skeptical pass/fail verdict with root cause. Use after writing or splitting a test, or to check if a suspected-flaky test reproduces.
---

# Verify E2E

Thin wrapper around the **`test-verifier`** subagent. Use this when you want a single test run + diagnosis, not the whole suite.

## Arguments

```
/verify-e2e <TestName>                # Auto-detect package
/verify-e2e <TestName> --serial       # Force the serial package
/verify-e2e <TestName> --parallel     # Force the parallel package
/verify-e2e <TestName> --expect "<expected outcome>"
```

`--expect` lets the verifier check more than just `go test` exit: e.g. `--expect "scan reaches PhaseDone with Result=COMPLIANT"`.

---

## Workflow

### 1. Locate the test

```bash
grep -rn "^func <TestName>(t \*testing.T)" tests/e2e/
```

If the test exists in both `parallel` and `serial`, error out — the user must disambiguate with `--serial` / `--parallel`.

### 2. Sanity-check cluster

```bash
oc whoami && oc get nodes && oc get pods -n openshift-compliance | head -20
```

If the operator namespace is missing, ask the user whether to run `make prep-e2e` — don't run it silently.

### 3. Hand off to test-verifier

Spawn the **`test-verifier`** subagent with:
- Test name
- Package (`parallel` or `serial`)
- Optional expected outcome

The agent will run the test, parse logs, classify the result, and produce the verdict block from `.claude/agents/test-verifier.md`.

### 4. Surface result

Print the verdict block as-is. If `FAIL`, include the agent's recommended next step.

---

## Discipline

- Don't run the full e2e suite from this skill. That's `make e2e` from the shell.
- Don't apply remediations or other mutating actions to the cluster outside the test itself.
- Don't loop a flaky test 10 times to "see if it's really flaky" without telling the user — that's expensive cluster time.
