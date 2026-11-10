---
name: ci-health
description: Analyzes Prow CI results for ComplianceAsCode/compliance-operator to separate flaky tests from real failures and infrastructure problems, then proposes fixes for the flakes. Use when the user asks why a test or job keeps failing, whether a failure is a flake, how healthy CI is, or wants a flaky test investigated or fixed.
argument-hint: [--limit N] [--job NAME] [--state open|merged|closed|all]
allowed-tools: Bash, Read, Grep, Glob
---

# CI Health

Analyzes recent Prow CI results for ComplianceAsCode/compliance-operator,
classifies failures as flaky / infrastructure / real, and proposes fixes for
the flaky ones.

For a plain volume and pass-rate snapshot without root-cause analysis, use
`/ci-activity` instead.

## Requirements

- `python3` 3.9 or newer, standard library only — no packages to install
- `gh` CLI, authenticated. Verify with `gh auth status` before Step 1; if it
  fails, tell the user to run `gh auth login` and stop.
- Network access to `prow.ci.openshift.org` and
  `storage.googleapis.com/test-platform-results`

## Arguments

- `--limit N` — number of PRs to analyze (default: 20)
- `--job <name>` — focus on one Prow job, e.g. `e2e-aws-serial`
- `--state <state>` — `open`, `merged`, `closed`, or `all` (default: `open`)
- No arguments — full analysis with defaults

## Step 1: Collect data

Run these from the repository root, in order — each reads the previous
script's output. Report progress as each completes.

```bash
python3 scripts/ci-health/fetch_prow_results.py --limit <LIMIT> --state <STATE> --output /tmp/ci-health-prow-results.json
python3 scripts/ci-health/detect_flakes.py --input /tmp/ci-health-prow-results.json --output /tmp/ci-health-flakes.json
python3 scripts/ci-health/fetch_failure_details.py --input /tmp/ci-health-flakes.json --output /tmp/ci-health-details.json
```

If any script exits non-zero, report its stderr and stop — do not run the
next one against a stale or missing file. These scripts are deterministic:
the same inputs produce the same classifications regardless of who runs them.

Note a `--job` argument for Step 2 filtering; the scripts do not take it.

## Step 2: Triage

Read `/tmp/ci-health-details.json` and sort results into three buckets:

1. **Flaky tests** — `flaky_tests` entries with `failure_count > 0`
2. **Infrastructure failures** — `infrastructure_failures` entries (cluster
   provisioning, DNS, ARM build issues)
3. **CI step failures** — `job_details` entries whose
   `dominant_failure_type` is `ci_step_failure` or `no_artifacts`

Apply the `--job` filter here if one was given.

```
## CI Health Triage

Analyzed N PRs with Prow checks.

| Category                | Count |
|-------------------------|-------|
| Flaky tests             | X     |
| Infrastructure failures | Y     |
| CI step failures        | Z     |
| Stable jobs             | W     |
```

Summarize each infrastructure and CI step failure in one line (job name and
error type). Do **not** attempt to fix them — they are platform-team issues.

A `no_artifacts` result means the expected build log was not found at the
path the script guessed. Treat it as "could not determine", not as "no
failure occurred".

If there are no flaky tests, report the triage table and stop. Skip Step 3.

## Step 3: Analyze and fix flaky tests

Only if Step 2 found flaky tests.

Read [fixing-flakes.md](fixing-flakes.md) for the root cause taxonomy, the
guardrails on what a fix may and may not do, and the proposal format. It
contains hard constraints — follow it rather than improvising a fix.

## Step 4: Report

```
## CI Health Report

### Overall Health
- Jobs passing: X/Y (Z%)
- Flaky tests found: N
- Infrastructure failures: M

### Flaky Test Details
(For each: name, root cause, confidence, proposed fix)

### Infrastructure Failures
(For each: job name, failure type, brief error description)

### Recommendations
- Priority 1: [highest-impact fix]
- Priority 2: [next fix]

### Next Steps
To apply a proposed fix, ask me to implement it — I'll need Edit permissions.
To re-run this analysis: /ci-health
To focus on a specific job: /ci-health --job <name>
```
