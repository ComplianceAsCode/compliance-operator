---
name: test-runtime
description: Extract per-test wall-clock runtime for the Compliance Operator e2e suite from prow's GCS artifacts. Aggregates across multiple recent runs to produce a sorted (mean, min, max, failure count) per-test table. Use to identify expensive tests when planning the test refactor or auditing CI cost.
---

# Test Runtime

Reads the actual `build-log.txt` Go test output from prow's GCS artifact tree and produces per-test runtime statistics. This is the canonical answer to "which tests are eating our CI time?"

## Arguments

```
/test-runtime                                # top 20 by mean runtime, parallel job, last 3 runs
/test-runtime --job <job-name>               # specific job
/test-runtime --runs N                       # aggregate over N most recent runs (default 3)
/test-runtime --top N                        # show top N tests (default 20)
/test-runtime --build-id <id>                # single specific build (skips aggregation)
```

Default job: `pull-ci-ComplianceAsCode-compliance-operator-master-e2e-aws-parallel`.

---

## Where the data lives

For PR-triggered jobs (`pull-ci-...`):

```
https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs/test-platform-results/
  pr-logs/pull/<repo_underscored>/<pr_num>/<job_name>/<build_id>/
    artifacts/
      e2e-aws-parallel/         (or e2e-aws-serial, etc — matches the job's test step name)
        test/
          build-log.txt         ← the file we want
```

For periodic jobs (`periodic-ci-...`):

```
https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs/test-platform-results/
  logs/<job_name>/<build_id>/
    artifacts/...
```

The build-log.txt contains Go's standard test output, with one `--- PASS:` or `--- FAIL:` line per top-level test:

```
--- PASS: TestSingleScanSucceeds (75.45s)
--- FAIL: TestParsingErrorRestartsParserInitContainer (1830.05s)
```

`(NNN.NNs)` is the wall-clock runtime that `go test` measured.

## Discovering recent build IDs

The prow job-history page is JavaScript-rendered, so curl/WebFetch won't see the build list. Two reliable sources:

1. **dptools search** (groupBy=none, type=junit): returns a flat list of `view/gs/...` URLs that you can derive build IDs from.

   ```
   https://search.dptools.openshift.org/?search=Test&type=junit&name=.*pull-ci-ComplianceAsCode-compliance-operator-master-e2e-aws-parallel$&maxAge=336h&maxMatches=20&groupBy=none&context=0
   ```

   Each result link looks like:
   ```
   https://prow.ci.openshift.org/view/gs/test-platform-results/pr-logs/pull/ComplianceAsCode_compliance-operator/<pr>/<job>/<buildId>
   ```

2. **Direct curl of job history HTML**: returns at least one build ID via the "older runs" link, but only one — the table itself is JS-populated.

   ```
   curl -s 'https://prow.ci.openshift.org/job-history/test-platform-results/pr-logs/directory/<job>' | grep -oE 'buildId=[0-9]+' | head -10
   ```

Use (1) for most cases. If dptools returns nothing (job is all-passes in the window), fall back to a search for a known passing test name like `TestSingleScanSucceeds` to force results.

---

## Workflow

1. **Resolve build IDs** — use dptools as above. For each result, parse `(repo, pr, job, buildId)` out of the URL.

2. **For each build, fetch the test log**:
   ```bash
   curl -s "https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs/test-platform-results/pr-logs/pull/<repo>/<pr>/<job>/<buildId>/artifacts/<job-suffix>/test/build-log.txt"
   ```
   `<job-suffix>` is usually the same as the job's trailing identifier (e.g. `e2e-aws-parallel` for the parallel job).

3. **Extract lines and parse**:
   ```bash
   grep -oE '^--- (PASS|FAIL): Test[A-Za-z_]+ \([0-9.]+s\)'
   ```
   Each line yields `(status, test_name, seconds)`.

4. **Aggregate** across runs into mean / min / max / failure-count per test name.

5. **Output**: descending by mean time, top N (default 20):

   ```markdown
   | Test | Runs | Mean (s) | Min | Max | Fails |
   |------|-----:|---------:|----:|----:|------:|
   | TestParsingErrorRestartsParserInitContainer | 3 | 1820.0 | 1815 | 1830 | 3/3 |
   | TestScheduledSuite | 3 | 385.1 | 385.0 | 385.2 | 0/3 |
   | ... |
   ```

   Also print: total cumulative test wall-time per run, mean across runs, and "what % of the cumulative time is from the top 10 tests."

---

## Known baseline (2026-05, parallel job, 3 recent runs)

- Cumulative test wall time per run: ~88-90 minutes (parallel suite).
- Top single contributor: `TestParsingErrorRestartsParserInitContainer` — 30 minutes per run, fails 3/3.
- Without the top contributor: ~58 min cumulative.
- Long-running tests (>60s mean): ~15 tests carry ~60% of total parallel wall time.

If your refactor goal is "reduce CI time," fixing the top flake alone reclaims ~34% of cumulative parallel-suite wall time.

---

## Discipline

- Don't paginate further than the user asks. Fetching 10 builds is ~3 MB of build-log; 30 builds gets noisy and slow.
- Cumulative test time is NOT the same as wall-clock job time. Tests use `t.Parallel()`, so the actual job wall-time is dominated by the slowest single test (1820s for the failing one, 385s for the next-slowest). Quote both numbers.
- For serial jobs, cumulative ≈ wall-clock because there's no parallelism.
- The build-log path inside `artifacts/` depends on the job's ci-operator step name. For the standard CO jobs it's `e2e-aws-parallel/test/`, `e2e-aws-serial/test/`, `e2e-aws-parallel-arm/test/`, `e2e-aws-serial-arm/test/`. If a job's artifact tree doesn't have that subdir, list `artifacts/` and find the analogous one.
