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

Use `/ci-search --jobs-only` to enumerate active CO jobs, then for each job query the JUnit failures:

```
/ci-search "FAIL: Test" --job <job-regex> --age 7d --type junit
```

The bare-test-name search (`/ci-search --test <TestName>`) gives the richest per-test view; use it for the top candidates after this aggregate query.

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
