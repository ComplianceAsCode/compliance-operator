---
name: deflake
description: Find the flakiest Compliance Operator tests using the OpenShift CI search index, rank them by failure rate × frequency, and plan deflake strategies. Use to drive periodic flake-cleanup sessions.
---

# Deflake

End-to-end deflake workflow for the Compliance Operator. Mines `search.dptools.openshift.org` for the noisy tests, classifies each (flake vs real bug vs env issue), and proposes fixes.

## Arguments

```
/deflake                  # Full analysis on last 7 days
/deflake --age 14d        # Wider window
/deflake --top N          # Plan fixes for the top N (default 3)
/deflake --report         # Report only; skip the fix-planning phase
```

---

## Phase 1: Collect

Job enumeration: read the "Known CO + content jobs" list in `/ci-search` SKILL.md (verified against prow) — do **not** rely on `/ci-search --jobs-only` to enumerate, because the dptools index is failure-focused and silently hides jobs that pass.

Then for each known job, query the JUnit failures:

```
/ci-search "FAIL: Test" --job <job-regex> --age 7d --type junit
```

The bare-test-name search (`/ci-search --test <TestName>`) gives the richest per-test view; use it for the top candidates after this aggregate query.

### Also pull runtime data

Failure rate alone undersells the cost of a flake. Run `/test-runtime` against the same jobs to get mean wall-time per test. Then rank candidates by a **cost score**, not just failure count:

```
cost = mean_runtime_seconds × failure_rate × estimated_runs_per_week
```

A 1820s test that fails 67% of the time eats orders of magnitude more CI budget than a 30s test that fails 20% of the time. Rank accordingly — that's what's actually worth your fix-time.

For a job that returns zero failures in the search (likely either healthy OR low-activity), confirm it actually ran by checking prow's history endpoint:
```
https://prow.ci.openshift.org/job-history/test-platform-results/pr-logs/directory/<job-name>
```
The "Showing N/M results" count tells you total historical runs. If M is non-trivial and dptools returns nothing, the job is likely healthy.

Aggregate per-test: total appearances, distinct jobs, failure rate, average duration, distinct error messages.

Rank by `(failure_rate × appearances × duration_seconds)` — a slow, frequently-failing test costs the most CI time.

---

## Phase 2: Categorize

For each candidate, classify per:

| Category | Signal | Action |
|----------|--------|--------|
| **Flake** | Intermittent fails interspersed with passes; same test passes minutes later. | Plan a fix below. |
| **Real bug** | Fails consistently after a known commit. Check `git log --since=<first-fail-date> -- pkg/ tests/` for the trigger. | Open an issue; do not deflake by hiding the symptom. |
| **Env issue** | Fails only on a specific job variant (e.g. only arm, only periodic). | Route to platform owner; consider job-level skip with tracking issue. |
| **Content drift** | Error mentions content image, profile parsing, missing rule. | Route to ComplianceAsCode/content. |

---

## Phase 3: Investigate (parallel)

For the top-N flakes the user wants planned, launch parallel **`general-purpose`** agents — one per flake. Each agent must:

1. Read the test source in `tests/e2e/` (or wherever `grep -rn "func TestName"` points).
2. Read the production code path the test exercises (controllers, framework helpers, reconcilers).
3. Pull 2–3 example failure logs from prow:
   ```bash
   # Get a sample failed run URL from the ci-search output, then:
   curl -s https://prow.ci.openshift.org/<...>/finished.json
   ```
4. Identify the root cause: timing race / shared state / external dep / cluster contention.
5. Map to the canonical fix bucket below.

**Launch in a single message** so they run concurrently.

### Post-hoc CI artifacts often can't prove a transient race

Before sinking time into log archaeology, know its ceiling. For a flake that's a
**transient race** (two pods, a status flap, a brief conflict), the end-state
prow artifacts frequently **cannot** show it:

- e2e tests tear down their objects with `defer ...Delete(...)`, so the failing
  ProfileBundle / scan / pods are **gone** by gather time.
- the compliance `must-gather` is often **empty (~76 bytes)** on CO jobs; even a
  real one (~20 MB) is a *generic* cluster gather that usually omits the
  `openshift-compliance` namespace pod logs.
- operator logs are **not** interleaved into the `go test` stdout (`build-log.txt`).

So the build-log usually gives you only the *symptom* (which assertion timed
out, e.g. `failed to reach state VALID`) — enough to **localize** the flake to a
code path, not to prove the mechanism. Use it to localize, then reproduce live.

### Validate the hypothesis on a live cluster — without rebuilding the operator

The fastest, most decisive step for a controller-side race: reproduce the
trigger on a cluster and watch the live objects. Crucially, you can often test a
**fix hypothesis** without building/pushing a new operator image, by patching
the live resource directly — the controller may not reconcile the field you're
testing.

Example (the ProfileBundle parser race, CMP-4324): drive the ProfileBundle
through the bad→good content-image transition and watch pod count / status /
restartCounts:

```bash
export KUBECONFIG=/tmp/x.kubeconfig   # never clobber the user's default kubeconfig
oc apply -f pb-bad.yaml               # contentImage :from  -> wait INVALID + parser restart
oc patch profilebundle X --type=merge -p '{"spec":{"contentImage":".../:to"}}'
# watch: are there 2 parser pods at once? does status flap? (that's the race window)
```

To test "would a Recreate strategy fix it?" patch the *existing* deployment and
re-run the transition — the controller's update path only copies `Spec.Template`,
so a manual `Spec.Strategy` patch sticks:

```bash
oc patch deploy <pb>-<ns>-pp -n openshift-compliance --type=merge \
  -p '{"spec":{"strategy":{"type":"Recreate","rollingUpdate":null}}}'
```

If the behavioral change you'd make in code (here: max 1 pod instead of 2) is
observable this way, you've validated the fix mechanism before writing it. Then
implement, and (optionally) `make image-to-cluster` for end-to-end proof. Always
clean up objects you created and the temp kubeconfig.

---

## Phase 4: Plan

For each flake produce:

```markdown
### Flake #N: TestName

**Job(s)**: list
**Failure rate**: X% over Y runs
**Avg duration**: Zs
**Sample runs**: <prow URLs>

**Root cause**: <one sentence>

**Options considered**:
1. Option A — <why rejected/chosen>
2. Option B — ...

**Recommended approach**: <chosen option>
- <high-level change>

**Confidence**: H / M / L
**Risk**: <what could break>
```

Present all plans to the user. **Do not edit any test code** until the user approves the approach.

---

## Fix Buckets (Compliance Operator specific)

| Bucket | When | Fix |
|--------|------|-----|
| **Polling timeout too tight** | `waitFor*` returns before status converges. | Bump the polling timeout in the framework helper, not in the test. Adds robustness everywhere. |
| **ProfileBundle race** | Test depends on a ProfileBundle reaching VALID; flaky on slow init container pulls. | Use `waitForProfileBundleStatus` with the existing helper; never assert state-change immediately after `Create`. |
| **ProfileBundle concurrent status writers** (CMP-4324) | A ProfileBundle's content image changes (e.g. broken→fixed) and it gets stuck non-VALID. The `profileparser` init container *writes the PB status*; under the parser Deployment's default RollingUpdate, the old pod keeps crash-looping (writing INVALID) while the new pod parses the fixed image (writing VALID) — two writers race. The parser also `os.Exit(1)`s on any status-update error, so a resourceVersion conflict CrashLoopBackOffs it. | Root cause is in the controller, not the test. Set the parser Deployment `Spec.Strategy.Type = Recreate` (single writer at a time) and wrap the parser's status write in `RetryOnConflict`. Validate live by patching the deployment strategy (see Phase 3). |
| **Shared scan namespace contention** | Two parallel tests racing on the same `default` ScanSetting. | Test should create its own ScanSetting with a unique name. |
| **MachineConfigPool churn (serial)** | Node remediation tests fail when MCP doesn't reach Updated within timeout. | Increase the per-test timeout; consider extracting the `mcTctx.ensureE2EPool()` setup to a fixture. |
| **Content image flakiness** | Failure logs reference `failed to parse` or `image pull`. | Not a CO issue — file with ComplianceAsCode/content. |
| **Operator restart races** | Operator pod restarts mid-test, test asserts a CR's status before reconcile catches up. | Test should poll status, not assert on a single Get. |

---

## Phase 5: Apply (only with approval)

Once a plan is approved, hand each fix off to the **`e2e-test-writer`** (test-only changes) or **`unit-test-writer`** (controller fix to address the underlying race). Each fix lands as its own commit so reverts are cheap.

After landing, re-run `/ci-search --test <TestName>` once a few CI runs have rolled in to confirm the failure rate dropped.

---

## Discipline (carried over from toolhive's deflake skill, adapted)

- **Prefer simplifying tests over adding complexity.**
- **Fix the test, not the production code** — unless the flake exposes a real race in the controller. Then fix the controller and keep the test.
- **Never `t.Skip`** a test to make CI green; that's a hidden regression source.
- **Never add `time.Sleep`** to "fix" timing. Use `wait.PollImmediate` / the framework helpers.
- **Don't widen production retry loops** to mask test flakes.
- **Don't remove the last e2e test** for a feature — at least one smoke test must remain.
