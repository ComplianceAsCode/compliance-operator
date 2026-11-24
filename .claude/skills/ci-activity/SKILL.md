---
name: ci-activity
description: Reports Prow CI job volume and pass/fail rates for ComplianceAsCode/compliance-operator over a recent time window, broken down by job. Use when the user asks how CI is doing, what the current pass rate is, which jobs are failing, or how much CI activity there has been in the last N hours.
argument-hint: [--hours N] [--e2e-only]
allowed-tools: Bash, Read
---

# CI Activity

Snapshot of recent CI volume and pass/fail breakdown for the
ComplianceAsCode/compliance-operator Prow jobs.

The Prow API retains roughly the last 24 hours of job data, so this reports a
current snapshot rather than a historical trend. For root-cause analysis of
the failures it surfaces, use `/ci-health`.

## Requirements

- `python3` 3.9 or newer, standard library only — no packages to install
- Network access to `prow.ci.openshift.org`

## Arguments

- `--hours N` — hours to look back, 1-24 (default: 24)
- `--e2e-only` — only include e2e jobs, the ones that provision clusters
- No arguments — last 24 hours, all job types

## Step 1: Collect data

Run from the repository root:

```bash
python3 scripts/ci-activity/fetch_ci_activity.py --hours <HOURS> [--e2e-only] --output /tmp/ci-activity.json
```

Pass `--e2e-only` only if the user asked to restrict to e2e jobs.

If the script exits non-zero, report its stderr to the user and stop. Do not
fetch Prow data another way — the script is the only supported source.

## Step 2: Present results

Read `/tmp/ci-activity.json`.

Pass rate is computed over **completed jobs only**; pending jobs are excluded
from the denominator. `pass_rate` is `null` when nothing has completed yet —
display that as `N/A`.

### Overall summary

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

If `pending` is greater than zero, add a note below the table:

> *N jobs still pending — pass rate reflects M completed jobs only.*

### Per-job breakdown

Sort by pass rate, worst first. Jobs with a `null` pass rate (all runs still
pending) sort to the top.

```
### Job Pass Rates

| Job                   | Runs | Passed | Failed | Pending | Pass Rate |
|-----------------------|------|--------|--------|---------|-----------|
| ci/prow/job-name      | N    | P      | F      | K       | R%        |
```

### Attention items

- Flag jobs at 0% pass rate as **always failing**
- Flag jobs below 50% pass rate as **frequently failing**
- Skip both thresholds for jobs with fewer than 3 completed runs; the rate is
  not meaningful yet. Say so rather than flagging them.
- If the overall pass rate is below 50%, suggest `/ci-health` for flake
  analysis and root cause investigation

### Next steps

Print:

```
To adjust the time window: /ci-activity --hours 12
To focus on e2e jobs only: /ci-activity --e2e-only
To deep-dive into flaky tests: /ci-health
```
