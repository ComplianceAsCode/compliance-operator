---
allowed-tools: Bash, Read
description: Show CI job activity and pass/fail rates over a time window
---

Show CI job volume and pass/fail breakdown for ComplianceAsCode/compliance-operator.

The Prow API endpoint only retains recent job data (roughly the last 24 hours),
so this skill provides a snapshot of recent CI activity, not historical trends.

Arguments: $ARGUMENTS

Supported arguments:
- `--hours N` — Number of hours to look back, 1-24 (default: 24)
- `--e2e-only` — Only include e2e jobs (the ones that provision clusters)
- No arguments — Last 24 hours, all job types

## Phase 1: Collect Data (Deterministic)

Parse the arguments to determine the `--hours` value (default 24) and whether
`--e2e-only` was passed.

Run the deterministic data collection script:

```
python3 scripts/ci-activity/fetch_ci_activity.py --hours <HOURS> [--e2e-only] --output /tmp/ci-activity.json
```

Report progress as the script runs.

## Phase 2: Present Results

Read `/tmp/ci-activity.json` and present the results.

### Overall Summary

Print a summary table. Pass rate is computed over **completed jobs only** (not
pending). If there are pending jobs, call them out separately:

```
## CI Activity — Last N Hours (HH:MM to HH:MM UTC)

| Metric            | Value |
|-------------------|-------|
| PRs               | X     |
| Total CI jobs     | Z     |
| Completed         | C     |
| Passed            | A     |
| Failed            | B     |
| Pending           | P     |
| Other             | O     |
| Overall pass rate | D%    |
```

Note: `pass_rate` in the JSON may be `null` when there are no completed jobs
(all pending). Display this as "N/A" in the table.

If there are pending jobs, add a note below the table:
> *N jobs still pending — pass rate reflects M completed jobs only.*

### Per-Job Breakdown

Print a table sorted by pass rate (worst first). Jobs with `null` pass rate
(all pending) sort to the top:

```
### Job Pass Rates

| Job                   | Runs | Passed | Failed | Pending | Pass Rate |
|-----------------------|------|--------|--------|---------|-----------|
| ci/prow/job-name      | N    | P      | F      | K       | R%        |
```

### Attention Items

- Flag any jobs with 0% pass rate as **always failing**
- Flag any jobs with < 50% pass rate as **frequently failing**
- If overall pass rate is below 50%, suggest running `/ci-health` for deeper
  flake analysis and root cause investigation

### Next Steps

Print:
```
To adjust the time window: /ci-activity --hours 12
To focus on e2e jobs only: /ci-activity --e2e-only
To deep-dive into flaky tests: /ci-health
```
