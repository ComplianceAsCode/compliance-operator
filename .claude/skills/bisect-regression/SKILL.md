---
name: bisect-regression
description: Find when a CI job started failing. Queries prow for the first failing run after a streak of passes, identifies the commit window between last green and first red, and produces candidate commits ranked by suspicion. Use when a periodic or PR job goes from green to red.
---

# Bisect Regression

When a CI job is failing 100% (or way above baseline), the question is: when did it start, and what commit broke it?

This is "git bisect" applied to CI history. The mechanics are different — you can't directly run CI on a single commit — but the inference works the same way.

## Arguments

```
/bisect-regression <job-name>                  # last 30 days
/bisect-regression <job-name> --since <date>   # custom window
/bisect-regression <job-name> --branch <name>  # default master
```

Example:

```
/bisect-regression periodic-ci-ComplianceAsCode-content-master-4.21-e2e-aws-openshift-node-compliance-weekly
```

---

## Workflow

### 1. Find the first failing run

Query prow's job history for the target job:

```
https://prow.ci.openshift.org/job-history/test-platform-results/logs/<job-name>
```

(Periodic jobs use `logs/`; PR jobs use `pr-logs/pull/<repo>/<pr>/`.)

The page renders status per run. Walk back through pages until you hit a transition from PASS → FAIL. Note:
- **last_green_timestamp**: the most recent passing run before the streak.
- **first_red_timestamp**: the first failing run.

### 2. Pull the commit window

For PR jobs, each run is tied to a PR + commit. The transition is unambiguous: PR X passed, PR Y failed; the diff is `git log X..Y`.

For periodic jobs (more common for regressions), the run isn't tied to a PR. Use the run's `started.json` to get the commit hash, then:

```bash
git log --since="<last_green_timestamp>" --until="<first_red_timestamp>" --oneline master
```

That's the candidate commit window.

### 3. Pull the failure log from the first red run

```bash
curl -s "https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs/test-platform-results/logs/<job-name>/<build-id>/artifacts/<step>/test/build-log.txt" \
  | grep -E '^--- (FAIL|RUN): Test' | tail -20
```

Identify the failing test name(s). If it's a new test that wasn't in the last green run, the regression is the test addition itself (or its setup). If it's a previously-passing test, the regression is in the code path the test exercises.

### 4. Map test name → likely code paths

For each failing test:

```bash
grep -rn "^func <TestName>" tests/e2e/
```

Read the test body. Identify:
- Which controller(s) it exercises (via the CRDs it creates/asserts).
- Which framework helpers it relies on.
- Which content fixtures it uses.

The candidate commits from step 2 that touch any of these are the suspects.

### 5. Rank candidates

For each commit in the window:

| Rank | Signal | Weight |
|------|--------|--------|
| Touches the failing test's exercised controller | High |
| Touches a framework helper the test uses | High |
| Touches a CRD type the test creates | High |
| Touches openscap/cel evaluation paths | Medium |
| Touches build/CI config | Medium (could be env, not code) |
| Touches docs/comments only | Low |

Output a ranked list of `(commit_sha, short_message, rank, why)`.

### 6. Suggest verification

For the top 1-3 candidates, suggest a local repro:

```bash
git checkout <commit>~1  # one before the suspect
make e2e-parallel E2E_GO_TEST_FLAGS="-v -run ^<TestName>$"
# If passes: confirm regression is in <commit>
git checkout <commit>
# Run again — if fails, you found it.
```

Don't auto-execute the checkout — it modifies the user's working tree.

---

## Output

```markdown
## Bisect: <job-name>

**Window**: <last_green_timestamp> (passing) → <first_red_timestamp> (failing).
**Streak**: N runs all failing since the transition.
**Failing test(s)**: TestX, TestY (citing prow build IDs).

### Candidate commits (in window, ranked)

| Rank | Commit | Author | Why suspicious |
|------|--------|--------|----------------|
| 1 | abc1234 | … | Touches <controller> reconcile loop; failing test exercises this code path. |
| 2 | def5678 | … | … |

### Recommended local verification

```bash
git checkout abc1234~1
make e2e-parallel E2E_GO_TEST_FLAGS="-v -run ^TestX$"
```
```

---

## Discipline

- **Don't blame the first commit in the window.** The transition might be caused by a content image push, an upstream dependency, or an env change — none of which appear in `git log`. Always read the build-log for the failure mode.
- **Periodic-only failures are often environment, not code.** A test that only fails on `4.21-arm-weekly` might be hitting an arm-specific bug, a cluster-bring-up flake, or a content compatibility issue. Confirm with the test's controller code, not the commit message.
- **The "candidate" list is heuristic, not authoritative.** It narrows the search space; it does not prove causation. Local repro is the only proof.
- **Don't suggest force-pushing or reverting** without explicit user authorization — those are destructive on a shared branch.

## Related

- `/ci-search` — for "is this failure already known"
- `/test-runtime` — for "is this test usually this slow"
- `/deflake` — once you've confirmed it's a flake, not a regression
