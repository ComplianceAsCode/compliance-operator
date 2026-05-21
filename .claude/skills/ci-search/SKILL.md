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

## Known CO jobs (as of 2026-05)

- `pull-ci-ComplianceAsCode-compliance-operator-master-e2e-aws-parallel`
- `pull-ci-ComplianceAsCode-compliance-operator-master-e2e-aws-parallel-arm`
- `pull-ci-ComplianceAsCode-compliance-operator-master-e2e-aws-serial` *(if present)*
- `periodic-ci-ComplianceAsCode-content-master-4.21-e2e-aws-openshift-node-compliance-weekly`
- `periodic-ci-ComplianceAsCode-content-master-4.21-e2e-aws-openshift-node-compliance-arm-weekly`

Use `--jobs-only` to discover the current set — the list rotates with OCP versions.

---

## Discipline

- Don't trust a 1-failure-out-of-2-runs signal. The CI window is short and the parallel suite has thin per-test runs. Cross-reference at least 5 recent runs before calling a test flaky.
- A failing periodic job (`periodic-ci-...`) may indicate environment/content issues, not operator regressions. Check whether the failing test exists upstream in `tests/e2e/`; if not, route to the content team rather than CO.
- A 100% failure rate on a periodic job that started failing on a specific date is usually a real regression, not a flake. `git log --since=<date>` to find candidate commits.
- The index prunes results older than 14d. Don't rely on it for historical trend analysis.
