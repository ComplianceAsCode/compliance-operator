---
allowed-tools: Bash, Read, Grep, Glob
description: Analyze Prow CI failures, detect flakes, and propose fixes
---

Analyze recent Prow CI results for ComplianceAsCode/compliance-operator, identify
flaky tests and infrastructure failures, and propose fixes for test-level issues.

Arguments: $ARGUMENTS

Supported arguments:
- `--limit N` — Number of PRs to analyze (default: 20)
- `--job <name>` — Focus on a specific Prow job (e.g., `e2e-aws-serial`)
- `--state <state>` — PR state filter: `open`, `merged`, `closed`, or `all` (default: `open`)
- No arguments — Full analysis with defaults

## Phase 1: Collect Data (Deterministic)

Parse the arguments to determine the `--limit` value (default 20), any `--job` filter,
and any `--state` filter (default `open`).

Run the Layer 1 pipeline. These scripts produce deterministic output — same input,
same results, regardless of who runs them.

```
python3 scripts/ci-health/fetch_prow_results.py --limit <LIMIT> --state <STATE> --output /tmp/ci-health-prow-results.json
python3 scripts/ci-health/detect_flakes.py --input /tmp/ci-health-prow-results.json --output /tmp/ci-health-flakes.json
python3 scripts/ci-health/fetch_failure_details.py --input /tmp/ci-health-flakes.json --output /tmp/ci-health-details.json
```

Run each script sequentially — each depends on the previous output. Report progress
as each script completes.

If a `--job` argument was provided, note it for Phase 2 filtering.

## Phase 2: Triage

Read `/tmp/ci-health-details.json` and separate results into three buckets:

1. **Flaky tests** — entries in `flaky_tests` with `failure_count > 0`
2. **Infrastructure failures** — entries in `infrastructure_failures` (cluster
   provisioning, DNS, ARM build issues)
3. **CI step failures** — entries in `job_details` with `dominant_failure_type`
   of `ci_step_failure` or `no_artifacts`

If a `--job` argument was provided, filter to only show results for that job.

Print a triage summary:

```
## CI Health Triage

Analyzed N PRs with Prow checks.

| Category              | Count |
|-----------------------|-------|
| Flaky tests           | X     |
| Infrastructure failures | Y   |
| CI step failures      | Z     |
| Stable jobs           | W     |
```

For infrastructure and CI step failures, print a brief summary of each (job name
and error type). Do NOT attempt to fix these — they are platform-team issues.

## Phase 3: Analyze Flaky Tests

For each flaky test identified in Phase 2:

1. Find the test source code:
   ```
   grep -rn "func <TestName>" tests/ pkg/
   ```

2. Read the full test function to understand what it does.

3. Read the error messages from the failure details JSON (the `error_summary`
   field in each occurrence).

4. If the error references specific source files or functions, read those too.

5. Determine the root cause category:
   - **Timing/race condition** — test waits for async operations with fixed
     timeouts or polling intervals
   - **Resource contention** — test uses shared cluster resources that may
     conflict with other tests
   - **External dependency** — test depends on external service availability
     (image registries, cloud APIs)
   - **Environment-specific** — fails only on specific architectures (ARM) or
     cluster configurations
   - **Actual bug** — test found a real but intermittent bug in product code

6. Assess fix confidence:
   - **High** — clear root cause, straightforward fix
   - **Medium** — likely root cause, fix may need validation
   - **Low** — unclear root cause or fix requires deep domain knowledge

## Phase 4: Propose Fixes

For each flaky test with medium or high confidence:

### GUARDRAILS — Read these before proposing ANY fix:

- **NEVER** delete test functions
- **NEVER** add `t.Skip()`, `Skip("")`, `Pending()`, or `XIt()` calls
- **NEVER** remove or comment out assertions
- **NEVER** weaken test conditions (e.g., changing exact match to contains)
- **NEVER** reduce test coverage
- **NEVER** add `//nolint` or suppress errors to make tests pass

### Acceptable fix categories:

- Adjust timeouts or polling intervals for async waits
- Add retry logic for operations that are inherently eventually-consistent
- Fix resource cleanup (ensure proper teardown between tests)
- Fix race conditions (add synchronization, proper ordering)
- Fix the production code under test if it has a real bug
- Improve error messages to make future debugging easier

### For each proposed fix:

1. Explain the root cause in 2-3 sentences
2. Show the proposed code change as a unified diff:
   ```diff
   --- a/tests/e2e/serial/main_test.go
   +++ b/tests/e2e/serial/main_test.go
   @@ ...
   - old code
   + new code
   ```
3. Explain why this fix addresses the flakiness
4. Note any risks or caveats

Do NOT apply the fix. Show it as text for the user to review.

## Phase 5: Report

Print a final structured report:

```
## CI Health Report

### Overall Health
- Jobs passing: X/Y (Z%)
- Flaky tests found: N
- Infrastructure failures: M

### Flaky Test Details
(For each flaky test: name, root cause, confidence, proposed fix)

### Infrastructure Failures
(For each: job name, failure type, brief error description)

### Recommendations
- Priority 1: [highest-impact fix]
- Priority 2: [next fix]
- ...

### Next Steps
To apply a proposed fix, ask me to implement it — I'll need Edit permissions.
To re-run this analysis: /ci-health
To focus on a specific job: /ci-health --job <name>
```
