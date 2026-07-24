---
name: babysit-ci
description: Watch a Compliance Operator PR's CI on an interval, report a compact per-job state each tick, and surface failures (fetch the build-log, classify build-vs-e2e-vs-infra). Use when the user wants to monitor/babysit/watch CI on a PR until it passes or fails.
---

# Babysit CI

Polls a PR's checks on a fixed cadence, reports a tight status line each tick, and the moment a job resolves calls it out — fetching the actual error for build failures. Stops itself when the watched jobs finish.

## Arguments

```
/babysit-ci <pr>                 # watch PR #<pr>, default 5m cadence, stop when build jobs resolve
/babysit-ci <pr> --interval 5m   # report cadence (Nm/Nh)
/babysit-ci <pr> --until build   # stop condition: build (default) | e2e | all
/babysit-ci <owner>/<repo>#<pr>  # explicit repo (default ComplianceAsCode/compliance-operator)
```

`--until build` = stop once verify/unit/images/go-build resolve (the fast verdict, ~10–25 min). `--until e2e` waits for the e2e jobs too (~2h). `--until all` also waits on Konflux.

---

## Critical: use the REST API, not `gh pr checks`

On this repo's auth, **GraphQL 401s** ("Requires authentication") but **REST works**. So `gh pr checks` / `gh pr view --json statusCheckRollup` fail — use `gh api` REST endpoints instead.

Two surfaces, fetched separately:

- **prow jobs → commit *statuses*** (`context` like `ci/prow/verify`):
  ```bash
  gh api "repos/$REPO/commits/$SHA/status" --jq '.statuses[] | "\(.state) \(.context)"'
  ```
- **GitHub Actions + Konflux → *check-runs***:
  ```bash
  gh api "repos/$REPO/commits/$SHA/check-runs" --jq '.check_runs[] | "\(.conclusion // .status) \(.name)"'
  ```

Resolve the PR head SHA first (force-pushes change it — always re-resolve):
```bash
SHA=$(gh api "repos/$REPO/pulls/$PR" --jq '.head.sha')
```

---

## Job taxonomy (what to watch)

| Group | Matcher | Notes |
|---|---|---|
| **build** (the verdict) | `ci/prow/(verify\|unit\|images\|go-build)` | fast (~10–25 min); compile/vet/build. **These are the signal.** |
| **e2e** | `ci/prow/e2e-*` | ~2h; gated behind `images`, so they stay `pending` until it passes |
| **konflux build** | check-run name `*-on-pull-request` | the container build |
| **konflux EC** | check-run name `*-enterprise-contract` | policy gate; **cascades** — `cancelled` when the build fails |
| process | `Milestone Check`, `tide`, `check-title` | usually pending/non-blocking |

States: prow statuses are `pending`/`success`/`failure`/`error`; check-runs use `conclusion` (`success`/`failure`/`cancelled`) or `status` (`in_progress`/`queued`) when not done.

---

## Workflow

### 1. Initial tick
Resolve SHA, pull both surfaces, print one compact line per PR:
```
#<pr>  build[ verify:success unit:success images:pending ]  e2e[ 7 pending ]  konflux[ in_progress ]
```

### 2. Arm the loop
Drive the cadence with a recurring job. Invoke `/loop <interval> <this assessment prompt>` (it sets up the cron and runs the first tick), **or** call `CronCreate` directly with `*/N * * * *` and a prompt that re-runs the assessment for this PR. Each fire: re-resolve SHA, report the line, check the stop condition.

### 3. On a build-job **failure**, fetch the error
Don't just say "failed" — get the cause. The status `target_url` is a prow URL; map it to the GCS build-log:
```bash
url=$(gh api "repos/$REPO/commits/$SHA/status" --jq '.statuses[]|select(.context=="ci/prow/verify")|.target_url')
gcs=${url#*/view/gs/}                                   # strip the prow viewer prefix
curl -s "https://storage.googleapis.com/$gcs/build-log.txt" | tail -40
```
- `verify`/`unit`/`go-build`/`images` → error is in the run-root `build-log.txt`.
- `e2e-*` → the Go failures are under `.../artifacts/<job>/test/build-log.txt` (grep `--- FAIL: Test`). See `/ci-search` for the GCS layout.

### 4. Classify the failure (so you report the right thing)
Parse the `could not run steps:` line from the build-log:
- **`pre steps failed`** → **infra** (cluster setup) — sub-categorize by the named pod: `ipi-install-install` (installer), `*-provision-*`/`vpc` (AWS/CloudFormation `ROLLBACK`), lease/boskos. Not the PR's fault; retryable.
- main `*-test` step failed → **test** failure (real or flake).
- Don't keyword-match the whole tail — the generic reason string `…utilizing_lease…` is on every run and will mis-flag test failures as infra.

(See `/deflake` and `/ci-search` for deeper triage and the infra-vs-flake split.)

### 5. Stop
When the `--until` group resolves (pass or fail): report the **final verdict**, fetch logs for any failures, and **delete the cron** (`CronDelete <id>`) so it stops firing. A short one-shot background `gh api` poll-until-resolved can run alongside as an early-exit signal.

---

## Compact tick recipe (drop-in)

```bash
REPO=ComplianceAsCode/compliance-operator
for PR in "$@"; do
  SHA=$(gh api "repos/$REPO/pulls/$PR" --jq '.head.sha' 2>/dev/null)
  bj=$(gh api "repos/$REPO/commits/$SHA/status" --jq '[.statuses[]|select(.context|test("prow/(verify|unit|images|go-build)$"))|"\(.context|sub("ci/prow/";"")):\(.state)"]|join(" ")' 2>/dev/null)
  e2e=$(gh api "repos/$REPO/commits/$SHA/status" --jq '[.statuses[]|select(.context|test("prow/e2e"))|.state]|group_by(.)|map("\(length) \(.[0])")|join(", ")' 2>/dev/null)
  kf=$(gh api "repos/$REPO/commits/$SHA/check-runs" --jq '[.check_runs[]|select(.name|test("on-pull-request"))|(.conclusion//.status)]|join(",")' 2>/dev/null)
  echo "#$PR  build[ ${bj:-none} ]  e2e[ ${e2e:-none} ]  konflux[ ${kf:-none} ]"
done
```

---

## Discipline

- **Re-resolve the head SHA every tick** — a force-push (common while fixing CI) moves it, and you'd otherwise watch a stale commit.
- **A clean PR may have *no* prow statuses yet** — release-1.* PRs often need a maintainer `/ok-to-test` before prow triggers. Report "no prow jobs yet" rather than "passing".
- **`images` gates e2e** — e2e staying `pending` while `images` runs is normal, not a hang.
- **Konflux `enterprise-contract: cancelled` is a cascade** from the build failing, not an independent failure — report the build cause, not EC.
- **Infra failures (`ipi-install-install`, VPC `ROLLBACK`, lease) are not the PR** — call them out as retryable; don't imply the code is broken. (The e2e suite here is ~60–90% infra-failure historically — see `/deflake`.)
- **Don't post anything to the PR** — this skill only reads. Posting is `/pr-review`.
- **Always `CronDelete` when done** so the loop doesn't keep firing after the verdict, and tell the user the job ID.
