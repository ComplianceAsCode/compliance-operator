---
name: ci-search
description: Query the OpenShift CI search index (search.dptools.openshift.org) for Compliance Operator and ComplianceAsCode/content test failures. Use to find how often a test has failed, in which jobs, with what error pattern, and how long it runs.
---

# CI Search

Thin wrapper around https://search.dptools.openshift.org — the indexed search interface for OpenShift CI job logs and JUnit results. It's the ground truth for "how flaky is this test?" and "which jobs run the CO e2e suite?"

## Arguments

```
/ci-search <regex>                             # search across CO + content jobs (last 7d)
/ci-search <regex> --age 14d                   # custom age window: 6h|12h|1d|2d|7d|14d
/ci-search <regex> --type junit                # junit (default) | build-log | bug | issue | all
/ci-search <regex> --job <regex>               # narrow to matching job names
/ci-search --test <TestName>                   # shortcut for "FAIL: <TestName>" against the CO jobs
/ci-search --jobs-only                         # list active CO jobs with run counts + failure rate
```

---

## URL Template

```
https://search.dptools.openshift.org/
  ?search=<urlencoded regex>
  &maxAge=<hours>h
  &context=1
  &type=<junit|build-log|bug|issue|all>
  &name=<urlencoded job-name regex>
  &excludeName=
  &maxMatches=15
  &maxBytes=20971520
  &groupBy=job
```

Default `name` regex for this repo:
```
.*compliance-operator.*|.*ComplianceAsCode.*
```

Use `type=junit` for test-name-level results, `type=build-log` for raw log grep.

---

## Workflow

### 1. Build the URL

URL-encode the `search` and `name` params. The CI index uses ripgrep regex (RE2-ish). What works in practice:

- **`<TestName>`** — searching the bare test name returns the richest results (the index indexes JUnit output, which contains the name verbatim). This is the recommended pattern for "how flaky is this one test?"
- **`FAIL: Test`** — useful for "give me every Go failure across all CO jobs in the window."
- `timed out waiting` — common scan-flake signature.
- `MachineConfigPools.*still updating` — node-remediation flake.
- `failed to reach state VALID` — ProfileBundle parsing flake.

What does NOT work well:

- `--- FAIL: Test` — the literal Go text marker isn't surfaced in `type=junit` results (those are XML), and the leading `---` can interact poorly with regex parsing. Use `FAIL: Test` or the test name instead.

### 2. Fetch

```
WebFetch https://search.dptools.openshift.org/?search=...&type=junit&...
```

Ask the model to extract: distinct job names, failure count per job, total runs per job, failure rate (%), test name, duration in seconds, error excerpt, sample timestamps.

### 3. Render

Output a compact table:

```markdown
| Test | Job | Runs | Fail % | Avg duration | Top error |
|------|-----|------|--------|--------------|-----------|
| TestParsingErrorRestartsParserInitContainer | pull-ci-…-parallel | 43 | 67% | 1820s | ProfileBundle failed to reach VALID |
```

If `--jobs-only`, drop the test column and just show job activity.

---

## What the dptools index is and isn't

This skill queries `search.dptools.openshift.org`, which is a **failure-focused** index of CI output (logs + JUnit). A job that passes consistently may not appear in search results even though it runs daily. **Do not infer job existence from search results.**

### For job enumeration

```
https://prow.ci.openshift.org/job-history/test-platform-results/pr-logs/directory/<job-name>
```

The page renders a count like "Showing 20/1224 results" — the second number is the total historical run count for that job, and its presence proves the job exists.

### For per-test runtime

The dptools index does NOT contain timing per Go test. For runtimes, go to the GCS artifact tree:

```
https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs/test-platform-results/
  pr-logs/pull/<repo>/<pr>/<job>/<buildId>/artifacts/<step>/test/build-log.txt
```

That file contains Go's `--- PASS: TestX (Ns)` / `--- FAIL: TestX (Ns)` lines. See `/test-runtime` for the workflow that aggregates these across runs.

### For build IDs of recent runs

The prow job-history page renders the run table client-side, so curl/WebFetch only see one build ID (the page's current cursor). Reliable enumeration sources:

- Use dptools with `groupBy=none` and any common test name — each result is a `view/gs/...` URL with the build ID in the last path segment.
- Or grep recent dptools failure results.

## GCS artifact archaeology (scripting against the bucket)

When you need to go past the dptools index into raw run artifacts (build-logs,
must-gather, gathered resources), hit the GCS bucket directly. Concrete recipes
and the traps that waste time:

**1. dptools JSON endpoint (not the HTML root).** For programmatic aggregation,
use `/search` (returns JSON keyed by run URL), not `/` (returns HTML):

```bash
curl -s "https://search.dptools.openshift.org/search?search=FAIL%3A%20Test&maxAge=336h&type=junit&name=<job>&groupBy=none&maxMatches=500"
# → { "<prow view URL>": { "FAIL: Test": [ { "context": ["--- FAIL: TestX (1830.05s)", ...] } ] }, ... }
```

Aggregate failures by test across runs:
```bash
jq -r '[.[] | .["FAIL: Test"][]?.context[]?] | .[]' out.json \
  | grep -oE 'FAIL: Test[A-Za-z0-9_]+' | sort | uniq -c | sort -rn
```

**2. Bucket = `test-platform-results`; object keys start at `pr-logs/...`.** The
single biggest time-sink: do **not** put the bucket name in the `?prefix=`. A
prow `view/gs/test-platform-results/pr-logs/...` URL includes the bucket; strip
it for the object API.

```bash
RUN="pr-logs/pull/ComplianceAsCode_compliance-operator/<pr>/<job>/<buildId>"   # NO leading test-platform-results/
# list immediate subdirs:
curl -s "https://storage.googleapis.com/storage/v1/b/test-platform-results/o?prefix=${RUN}/artifacts/<job>/&delimiter=/&fields=prefixes" | jq -r '.prefixes[]?'
# fetch a file (this host DOES take the bucket in the path):
curl -s "https://storage.googleapis.com/test-platform-results/${RUN}/artifacts/<job>/test/build-log.txt"
```

**3. Go test stdout lives at** `artifacts/<job-step>/test/build-log.txt` (the
step name == the test name, e.g. `e2e-aws-parallel`). The failing assertion line
(`main_test.go:NNN: ... failed to reach state VALID`) is the symptom; line
numbers shift per PR, so key off the *message*, not the number.

**4. must-gather is usually useless for CO flakes.** Check size before
downloading: `curl -sI .../gather-must-gather/artifacts/must-gather.tar | grep -i content-length`.
A **76-byte** tar is empty (common); even a real ~20 MB one is a *generic*
cluster gather that typically omits the `openshift-compliance` namespace pod
logs. Operator/parser pod logs and transient PB/scan objects are generally
**not** recoverable post-hoc (tests `defer Delete` them) — reproduce live
instead (see `/deflake` Phase 3).

## Known CO + content jobs (verified 2026-05-21 against prow + dptools)

**Pull-request jobs (compliance-operator):**
- `pull-ci-ComplianceAsCode-compliance-operator-master-e2e-aws-parallel` — ~67% failure rate (per dptools, 14d window). Dominant failure: `TestParsingErrorRestartsParserInitContainer`.
- `pull-ci-ComplianceAsCode-compliance-operator-master-e2e-aws-parallel-arm` — ~77% failure rate, same.
- `pull-ci-ComplianceAsCode-compliance-operator-master-e2e-aws-serial` — 1224 historical runs on prow; rarely surfaces in dptools (low failure rate or fewer indexed events).
- `pull-ci-ComplianceAsCode-compliance-operator-master-e2e-aws-serial-arm` — 1171 historical runs on prow; same.

The serial jobs are the reason the apparent failure rate of CO PR CI is overstated when you only look at `parallel*` — the serial jobs run in parallel with them and pass at a much higher rate.

**Periodic jobs (content):**
- `periodic-ci-ComplianceAsCode-content-master-4.21-e2e-aws-openshift-node-compliance-weekly`
- `periodic-ci-ComplianceAsCode-content-master-4.21-e2e-aws-openshift-node-compliance-arm-weekly`
- `periodic-ci-ComplianceAsCode-content-master-4.18-e2e-aws-openshift-node-compliance-weekly`
- `periodic-ci-ComplianceAsCode-content-master-4.16-e2e-aws-openshift-node-compliance-weekly`
- `periodic-ci-ComplianceAsCode-content-master-4.19-e2e-aws-openshift-node-compliance-arm-weekly`

The 4.21 periodics have been failing 100% over multiple weeks — that's a real regression in the content side, not a flake. Use `/deflake` for triage but route the fix to the content team.

To discover the current set of periodic jobs (the OCP-version list rotates), run a broad search-only `/ci-search` AND cross-reference with prow's directory listing — the periodic_failure rate makes search a reasonable enumeration source for them.

---

## Discipline

- Don't trust a 1-failure-out-of-2-runs signal. The CI window is short and the parallel suite has thin per-test runs. Cross-reference at least 5 recent runs before calling a test flaky.
- A failing periodic job (`periodic-ci-...`) may indicate environment/content issues, not operator regressions. Check whether the failing test exists upstream in `tests/e2e/`; if not, route to the content team rather than CO.
- A 100% failure rate on a periodic job that started failing on a specific date is usually a real regression, not a flake. `git log --since=<date>` to find candidate commits.
- The index prunes results older than 14d. Don't rely on it for historical trend analysis.
