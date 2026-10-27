# Analyzing and Fixing Flaky Tests

## Contents

- Guardrails — hard constraints on what a fix may do
- Investigating a flaky test
- Root cause categories
- Confidence levels
- Acceptable fix categories
- Proposal format
- Worked example

## Guardrails

Read these before proposing **any** fix. They are not negotiable, and they
override anything a root cause analysis seems to suggest.

- **NEVER** delete test functions
- **NEVER** add `t.Skip()`, `Skip("")`, `Pending()`, or `XIt()` calls
- **NEVER** remove or comment out assertions
- **NEVER** weaken a test condition, such as changing an exact match to a
  substring match
- **NEVER** reduce test coverage
- **NEVER** add `//nolint` or otherwise suppress errors to make a test pass

A test that is hard to fix stays failing and gets reported. Silencing it is
worse than leaving it red.

## Investigating a flaky test

For each flaky test from the triage step:

1. Find the source:
   ```bash
   grep -rn "func <TestName>" tests/ pkg/
   ```
2. Read the full test function.
3. Read the `error_summary` field for each occurrence in
   `/tmp/ci-health-details.json`.
4. If an error references other source files or functions, read those too.
5. Assign a root cause category and a confidence level, both below.

Compare the occurrences against each other. A test that fails the same way
every time is usually a real bug; one that fails differently each run is
usually timing or contention.

## Root cause categories

- **Timing / race condition** — waits on an async operation with a fixed
  timeout or polling interval that is too tight under CI load
- **Resource contention** — uses shared cluster resources that collide with
  other tests running concurrently
- **External dependency** — depends on an outside service being reachable,
  such as an image registry or cloud API
- **Environment-specific** — fails only on certain architectures (ARM) or
  cluster configurations
- **Actual bug** — the test found a real but intermittent product bug

## Confidence levels

- **High** — clear root cause, straightforward fix
- **Medium** — likely root cause, the fix needs validation
- **Low** — unclear root cause, or fixing it needs domain knowledge not
  available from the logs

Propose fixes only for **medium** and **high**. For **low**, report the
evidence gathered and say what additional information would settle it.

## Acceptable fix categories

- Adjust timeouts or polling intervals for async waits
- Add retry logic for operations that are genuinely eventually-consistent
- Fix resource cleanup so teardown is reliable between tests
- Fix race conditions by adding synchronization or ordering
- Fix the production code under test when it has a real bug
- Improve error messages to make the next failure easier to diagnose

## Proposal format

For each proposed fix:

1. State the root cause in two or three sentences.
2. Show the change as a unified diff.
3. Explain why it addresses the flakiness specifically, not just the symptom.
4. Note risks and caveats, including how much wall-clock time a longer
   timeout adds to a passing run.

Do **not** apply the fix. Present it as text for the user to review.

## Worked example

**Test:** `TestScanCleanup` — failed on 3 of 7 PRs, all on different
branches, each time with `2 scans not cleaned up`.

**Root cause:** Timing. `WaitForScanCleanup` polls for scan deletion for two
minutes. Scan teardown has to wait for the operator to finalize each
`ComplianceScan`, which on a loaded cluster regularly exceeds that. The
failures cluster on `e2e-aws-serial`, which runs the most scans per suite.

**Proposed change:**

```diff
--- a/tests/e2e/framework/common.go
+++ b/tests/e2e/framework/common.go
@@ -269,7 +269,7 @@ func (f *Framework) WaitForScanCleanup() error {
-	timeouterr := wait.Poll(time.Second*5, time.Minute*2, func() (bool, error) {
+	// Scan finalization waits on the operator to tear down each scan's pods;
+	// under e2e-aws-serial load this regularly exceeds two minutes.
+	timeouterr := wait.Poll(time.Second*5, time.Minute*5, func() (bool, error) {
 		var scans compv1alpha1.ComplianceScanList
 		f.Client.List(context.TODO(), &scans, &dynclient.ListOptions{})
 		if len(scans.Items) == 0 {
```

**Why this fixes it:** The deletion does complete; the test gives up early.
The poll already returns as soon as the list is empty, so the longer bound
costs nothing on a healthy run.

**Risks:** A genuine cleanup hang now takes five minutes to surface instead
of two. If this test starts timing out at five minutes, the cause is a real
finalizer deadlock rather than load, and should be investigated as a product
bug rather than raised again.
