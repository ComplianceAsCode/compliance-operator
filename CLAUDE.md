# CLAUDE.md

Guidance for Claude Code when working in the Compliance Operator repo.

## Project Overview

The Compliance Operator (CO) runs compliance scans on OpenShift / Kubernetes clusters using OpenSCAP (and, for CEL-based rules, native Go evaluation). It is an Operator-SDK / controller-runtime project. Core CRDs live in `pkg/apis/compliance/v1alpha1/`; controllers in `pkg/controller/`; shared helpers in `pkg/utils/`; profile parsing in `pkg/profileparser/`.

End-to-end tests live in `tests/e2e/` and run against a real OpenShift cluster.

## Build and Development Commands

```bash
make test-unit          # Unit tests (pkg/)
make e2e                # Full e2e against the current cluster (parallel + serial)
make e2e-parallel       # Parallel-safe e2e tests only
make e2e-serial         # Disruptive / serial e2e tests
make e2e-rosa           # Parallel suite tuned for managed ROSA
make verify             # go vet + gosec
make fmt simplify       # gofmt
make manifests generate # Regenerate CRD manifests + deepcopy
```

**Never** run `go test ./tests/e2e/...` directly. The Makefile sets `CONTENT_IMAGE`, `BROKEN_CONTENT_IMAGE`, and `prep-e2e` deploys CRDs and operator manifests from `tests/_setup/` — invoking `go test` directly skips that prep.

Single test: `make e2e-parallel E2E_GO_TEST_FLAGS="-v -timeout 45m -run TestSingleScanSucceeds"`.

## Test Layout

| Path | Purpose |
|------|---------|
| `tests/e2e/parallel/main_test.go` | All parallel-safe e2e tests (currently one ~200K-line file). |
| `tests/e2e/serial/main_test.go` | Disruptive/serial e2e tests. |
| `tests/e2e/rosa/main_test.go` | ROSA-platform variant. |
| `tests/e2e/framework/` | Shared helpers: `framework.go`, `common.go`, `utils.go`. |
| `tests/data/` | Datastreams, tailoring inputs, CEL bundles. |
| `pkg/**/*_test.go` | Unit tests colocated with code. |

There is an active testing-refactor effort (see `testing-refactor.md`) to split the monolithic `parallel/main_test.go` into per-feature suites. Use the `/analyze-tests`, `/split-test-file`, and `/triage-downstream` skills.

## CI Visibility

CI visibility uses two endpoints:

- **Failure search**: https://search.dptools.openshift.org (14-day retention, failure-focused — passing jobs may not appear).
- **Job enumeration / history**: https://prow.ci.openshift.org/job-history/test-platform-results/pr-logs/directory/&lt;job-name&gt; (full history, source of truth for "does this job exist").

Active CO PR jobs (2026-05): `pull-ci-…-e2e-aws-parallel`, `…-parallel-arm`, `…-e2e-aws-serial`, `…-serial-arm`. Plus weekly `periodic-ci-ComplianceAsCode-content-master-<ocp>-…` runs.

Tools:
- `/ci-search --test <TestName>` — failure history for one test.
- `/ci-search --jobs-only` — enumerate failing jobs in the window (note: passes-only jobs hide).
- `/deflake` — mine flaky tests, classify, plan fixes.

## Available Subagents

Agents live in `.claude/agents/`. Invoke for matching work:

### Test refactor pipeline (primary use case)
- **test-analyzer** — classifies each `Test*` function by `feature_group` + `operation_type`, emits structured JSON.
- **test-suite-planner** — takes classification output and proposes the per-suite file split.
- **test-verifier** — runs a specific e2e test against the cluster and analyzes the result.
- **downstream-test-triager** — investigates `NOTE(rhmdnd)` markers and maps downstream OpenShift QE tests to upstream coverage.

### User-invocable skills

- `/analyze-tests` — full classify-and-plan pipeline for the parallel-suite refactor.
- `/split-test-file <feature_group>` — mechanically extract one feature_group out of `main_test.go`.
- `/add-e2e-test "<description>"` — guided new test creation in the right file.
- `/triage-downstream <path>` — `NOTE(rhmdnd)` → Jira drafts.
- `/verify-e2e <TestName>` — run one test + skeptical verdict.
- `/ci-search <regex>` — query the OpenShift CI search index.
- `/deflake [--top N]` — rank flakiest tests and plan fixes.
- `/pr-review <pr#>` — post inline review comments via `gh`.

### Development
- **compliance-operator-expert** — codebase navigation, design history, where things live.
- **e2e-test-writer** — write new e2e tests against `tests/e2e/framework`.
- **unit-test-writer** — write unit tests in `pkg/`.
- **code-reviewer** — review changes for Go style, operator patterns, security.

## Key Conventions

Path-scoped rules in `.claude/rules/` are auto-loaded when matching files are touched:

- **Go style**: `.claude/rules/go-style.md` (`**/*.go`)
- **E2E tests**: `.claude/rules/testing-e2e.md` (`tests/e2e/**`)
- **Unit tests**: `.claude/rules/testing-unit.md` (`pkg/**/*_test.go`)
- **Controllers**: `.claude/rules/controller.md` (`pkg/controller/**`)
- **CRDs**: `.claude/rules/crd.md` (`pkg/apis/**`)

## Things That Will Bite You

- The e2e parallel suite uses `t.Parallel()`; tests share a single namespace and operator deployment. New tests must be namespace-isolated by creating their own ProfileBundles / ScanSettings, and must not modify any cluster-global resource (no node taints, no MachineConfig apply) — those belong in `tests/e2e/serial/`.
- `framework.Framework` is initialized in `TestMain` and exposed via `framework.Global`. Don't construct a second framework.
- A scan failure in e2e most often means content image mismatch (`CONTENT_IMAGE` / `BROKEN_CONTENT_IMAGE`), missing `prep-e2e` prep, or a previous test left state behind. Re-run `make prep-e2e` and inspect operator logs before assuming a regression.
- `make verify-bundle` will fail in CI if you forget `make manifests generate` after CRD edits.
- The downstream OpenShift QE suite lives in a different repo (`openshift/openshift-tests-private`). Many of its tests overlap with upstream — see `testing-refactor.md` for the consolidation plan.

## PR Guidelines

- Imperative subject, no Conventional Commits prefix.
- Don't push to remote without explicit user approval.
- Include `make verify` + relevant test runs in the PR description.
