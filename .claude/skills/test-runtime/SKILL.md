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

Two reliable sources, **in this order**:

1. **Prow job-history HTML, grepped for long numerics**: even though the table is JS-rendered, the HTML embeds build-ID-shaped paths in href attributes. This reliably returns ~20 build IDs and is independent of search-index coverage.

   ```bash
   curl -s 'https://prow.ci.openshift.org/job-history/test-platform-results/pr-logs/directory/<job>' \
     | grep -oE '/[0-9]{15,}' | sort -u
   ```

   Each match is `/<buildId>`; strip the leading slash.

2. **dptools search** (groupBy=none, type=junit): returns a flat list of `view/gs/...` URLs that you can derive `(repo, pr, job, buildId)` from. Use this if you specifically want builds that exercised a test or failure mode.

   ```
   https://search.dptools.openshift.org/?search=Test&type=junit&name=.*pull-ci-ComplianceAsCode-compliance-operator-master-e2e-aws-parallel$&maxAge=336h&maxMatches=20&groupBy=none&context=0
   ```

   Each result link looks like:
   ```
   https://prow.ci.openshift.org/view/gs/test-platform-results/pr-logs/pull/ComplianceAsCode_compliance-operator/<pr>/<job>/<buildId>
   ```

If dptools returns nothing (job is all-passes), the job-history method is the only one that works.

### Mapping a build ID to its PR (needed for the gcsweb URL)

For PR jobs, the gcsweb path requires the PR number. Resolve it by fetching the symlink target file at:

```
https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs/test-platform-results/pr-logs/directory/<job>/<buildId>.txt
```

That file's content is the `gs://...pr-logs/pull/<repo>/<pr>/<job>/<buildId>` symlink target — parse `<pr>` out.

### Filter out install-failed builds

A non-trivial fraction of PR-job builds fail at cluster install before any test runs. Their `artifacts/<step>/test/build-log.txt` URL returns the directory listing (HTML) instead of a real log. Detect with a size threshold:

```bash
size=$(curl -s -o /tmp/build-log -w '%{size_download}' "<url>")
if [ "$size" -lt 100000 ]; then echo "skip: install-failed or empty"; fi
```

Expect to fetch ~13-15 build IDs to land 10 with valid test data.

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

5. **Output**: descending by mean time, top N (default 20). Include std-dev:

   ```markdown
   | Test | Runs | Mean (s) | Min | Max | StdDev | Fails |
   |------|-----:|---------:|----:|----:|-------:|------:|
   | TestParsingErrorRestartsParserInitContainer | 13 | 1820.0 | 1815 | 1830 | 4.2 | 4/13 |
   | TestScheduledSuite | 13 | 385.1 | 285.0 | 700.3 | 145.2 | 0/13 |
   | ... |
   ```

   Also print:
   - Total cumulative test wall-time per run, mean across runs.
   - What % of cumulative time the top 10 tests carry.
   - "High variance" callout: tests where `(max-min)/mean > 0.5` AND `mean > 1s` (the mean-filter guards against sub-second jitter on fast tests).
   - "Stable-but-slow" callout: tests with `mean > 60s` AND `stddev/mean < 0.1`. These are intrinsic-work tests, not flake candidates — optimizing them needs scope-reduction, not deflake.
   - "Bimodal" callout: a test whose runs cluster around two distinct values (e.g. parser-restart at 75s healthy vs 1820s flake). Different remediation than high-variance — these are flakes that fail-loud.

---

## Known baseline (2026-05, parallel job, 13 healthy runs)

- Mean cumulative test wall time per run: ~68 minutes (range 54-89 min).
- Bimodal distribution: 9 healthy runs ~56 min, 4 flake runs ~87 min — the gap is one parser-restart timeout.
- `TestParsingErrorRestartsParserInitContainer`: fails 4/13 (31%) and consumes 1820s when it fails. **Single biggest CI-cost target.** Fixing it reclaims ~22% of mean cumulative wall-time.
- Top 10 tests carry ~50% of cumulative; top 20 carry ~71%.
- `TestScheduledSuite`: high variance (285-700s) on a recent 13-run window — newly visible signal, worth investigating (CronJob scheduler tick drops or API contention).
- 4-test cluster sharing a "30-50% variance, 75-155s" signature suggests `waitForScanStatus` poll-loop tightness — single fix may improve all four.

If your refactor goal is "reduce CI time," fixing the top flake alone reclaims ~22% of cumulative parallel-suite wall time.

---

## Discipline

- Don't paginate further than the user asks. Fetching 10 builds is ~3 MB of build-log; 30 builds gets noisy and slow.
- Cumulative test time is NOT the same as wall-clock job time. Tests use `t.Parallel()`, so the actual job wall-time is dominated by the slowest single test (1820s for the failing one, 385s for the next-slowest). Quote both numbers.
- For serial jobs, cumulative ≈ wall-clock because there's no parallelism.
- The build-log path inside `artifacts/` depends on the job's ci-operator step name. For the standard CO jobs it's `e2e-aws-parallel/test/`, `e2e-aws-serial/test/`, `e2e-aws-parallel-arm/test/`, `e2e-aws-serial-arm/test/`. If a job's artifact tree doesn't have that subdir, list `artifacts/` and find the analogous one.
