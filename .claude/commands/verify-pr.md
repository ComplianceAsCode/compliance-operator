---
name: verify-pr
description: Verify a compliance-operator PR fix on a live OCP cluster — builds image, deploys operator, runs e2e tests, performs manual verification, and optionally generates a Jira-ready report.
---

# /verify-pr — PR Verification on Live Cluster

You are an automated PR verification assistant for the compliance-operator project. Walk through the phases below interactively, asking the user for input at each decision point.

## Phase 1: Gather Inputs

Ask the user for the following (use AskUserQuestion for choices, accept free-text for paths/URLs):

1. **PR number**: Which PR to verify? Default to the current branch if the user says "current branch".
   - If a PR number is given, run `gh pr view <number> --json title,body,headRefName,files` to fetch details.
   - If using the current branch, run `git log master..HEAD --oneline` to understand the changes.

2. **Kubeconfig path**: Ask for the path to the kubeconfig file for the target cluster.
   - Validate it works: `KUBECONFIG=<path> oc get clusterversion -o jsonpath='{.items[0].status.desired.version}'`
   - Show the cluster version and node count to the user.

3. **Operator image**: Ask the user to choose:
   - **Build from current branch**: Build locally with `make image` and push to a registry.
     - Ask for the registry (e.g. `quay.io/rh-ee-thafeez`). Confirm they are logged in with `podman login <registry> --get-login`.
     - The image tag should be `pr<number>` (e.g. `quay.io/rh-ee-thafeez/compliance-operator:pr1263`).
     - Remind the user to make the repository **public** on quay.io after the first push.
   - **Use a pre-built image**: Accept the full image URL (e.g. `quay.io/someone/compliance-operator:sometag`).

Set `KUBECONFIG` as an environment variable for all subsequent commands:
```
export KUBECONFIG=<path>
```

## Phase 2: Build & Push (if building from branch)

Only if the user chose to build from the current branch:

1. Run `make image IMG=<registry>/compliance-operator:<tag>` to build the operator image with the correct tag directly (e.g. `make image IMG=quay.io/rh-ee-thafeez/compliance-operator:pr1263`). No separate `podman tag` step needed.
2. Push it: `podman push <registry>/compliance-operator:<tag>`
3. Check if user is logged in `podman login <registry>` and push image only if its logged in. If it fails with auth errors, tell the user to run `podman login <registry>` and retry.

## Phase 3: Clean Up & Deploy

### 3a. Clean up leftover resources from previous runs

Run these cleanup commands (ignore errors — resources may not exist):

```bash
# Delete leftover test namespaces
make tear-down
oc get ns -o name | grep osdk-e2e | xargs -r oc delete --wait=false

# Delete compliance CRDs
oc get crd -o name | grep compliance | xargs -r oc delete

# Delete cluster-scoped RBAC from e2e framework
oc get clusterrole -o name | grep -iE 'compliance|profilebundle|scansetting|tailoredprofile|remediation-aggregator|api-resource-collector' | xargs -r oc delete
oc get clusterrolebinding -o name | grep -iE 'compliance|api-resource-collector|remediation-aggregator' | xargs -r oc delete

# Delete MachineConfigPools and node labels
oc get machineconfigpool -o name | grep e2e | xargs -r oc delete
oc get nodes -l node-role.kubernetes.io/e2e -o name | xargs -r -I{} oc label {} node-role.kubernetes.io/e2e-
```

Wait until CRDs and namespaces are fully gone before proceeding:
```bash
oc get crd -o name | grep compliance  # should return nothing
oc get ns -o name | grep osdk-e2e     # should return nothing
```

### 3b. Deploy the operator for manual verification

Deploy the operator using `make deploy` so it stays running for manual verification. Do NOT use `make e2e-deployment` — that target runs tests and tears everything down automatically.

```bash
make deploy IMG=<operator-image>
```

Then wait for the operator pod and ProfileBundles to be ready:
```bash
oc wait --for=condition=Ready pod -l name=compliance-operator -n openshift-compliance --timeout=120s
# Wait for ProfileBundles to reach VALID status
oc get profilebundle -n openshift-compliance
```

Note: The e2e tests in Phase 4 deploy their own operator instance separately (in an `osdk-e2e-*` namespace) and clean it up when done. The `make deploy` instance in `openshift-compliance` is only for Phase 5 manual verification.

## Phase 4: Auto-detect and Run E2E Tests

### 4a. Discover tests from the PR

Fetch the PR diff and look for new or modified test files:

```bash
gh pr diff <number> --name-only | grep '_test.go$'
```

For each test file found, extract test function names:
```bash
gh pr diff <number> | grep '^+func Test' | sed 's/^+func \(Test[^(]*\).*/\1/'
```

Also check which test directory the tests are in to determine the right make target:
- `tests/e2e/serial/` → `make e2e-serial`
- `tests/e2e/parallel/` → `make e2e-parallel`
- `tests/e2e/deployment/` → `make e2e-deployment`

### 4b. Confirm with user

Present the discovered tests to the user using AskUserQuestion. Show:
- The test function names found
- Which make target to use
- Let them confirm, modify the list, or add additional tests.

### 4c. Run the tests

Run the confirmed tests. Example:

```bash
make e2e-serial \
  IMG=<operator-image> \
  E2E_GO_TEST_FLAGS="-v -run <TestName1>|<TestName2> -test.timeout 30m"
```

Run this in the background and monitor the output. Report pass/fail when complete.

If the test fails, show the relevant error lines and ask the user if they want to:
- Retry after cleanup
- Skip to manual verification
- Abort

## Phase 5: Manual Verification

### 5a. Analyze the PR changes

Read the PR diff and description to understand:
- What bug was fixed
- What behavior changed
- What resources/metrics/status fields are affected

### 5b. Design verification steps

Based on the PR analysis, design a sequence of manual verification steps. Common patterns include:

- **Metric fixes**: Create a ComplianceSuite → check metric → restart operator → check metric again → delete suite → check metric is gone
- **Status/result fixes**: Create a scan → check status → trigger a re-scan or condition change → verify status updates correctly
- **Remediation fixes**: Create a scan → apply/unapply remediations → verify the fix
- **Profile/content fixes**: Create a ProfileBundle or TailoredProfile → verify parsing/behavior

For querying the metrics endpoint, use this pattern:
```bash
oc create sa metrics-test-sa -n <namespace>
oc adm policy add-cluster-role-to-user cluster-monitoring-view -z metrics-test-sa -n <namespace>
TOKEN=$(oc create token metrics-test-sa -n <namespace>)
oc run --rm -i --restart=Never \
  --image=registry.fedoraproject.org/fedora-minimal:latest \
  -n <namespace> metrics-check-<unique-suffix> -- \
  bash -c "curl -ks -H 'Authorization: Bearer $TOKEN' \
  https://metrics.<namespace>.svc:8585/metrics-co" \
  | grep <metric-name>
```

### 5c. Execute and log

Run each manual step, capturing the command and its output. Log results as:
- PASSED: Expected output matched
- FAILED: Expected output did not match (show what was expected vs actual)

If the e2e test already covered all scenarios and passed, ask the user if they still want manual verification or want to skip to the report.

## Phase 6: Report

Ask the user: "Do you want me to generate a Jira-ready verification report?"

If yes, generate a formatted report containing:

```
**PR <number> (<Jira-ID>) — E2E and Manual Verification on Live OCP Cluster**

**Cluster**: OCP <version> (<node-count> masters, <node-count> workers on <platform>)
**Operator Image**: `<image-used>`

---

**1. Automated E2E Test — <PASSED/FAILED>**

\```
<key test output lines — RUN, PASS/FAIL, relevant metric/status lines>
\```

---

**2. Manual Verification — <All N Fixes Confirmed / X of N Confirmed>**

**2a. <Description of fix 1>**
\```
<commands and output>
\```
Result: <PASSED/FAILED>

**2b. <Description of fix 2>**
...

---

**Summary**: <one-line summary of results>
```

## Phase 7: Cleanup

After verification is complete, ask the user if they want to clean up the cluster resources:
- Delete the test namespace, CRDs, ClusterRoles, MCPs, node labels using `make tear-down`
- Or leave the operator running for further investigation

## Important Notes

- Always use `export KUBECONFIG=<path>` prefix for oc/kubectl commands.
- **Do NOT ask the user for approval on each `oc apply`, `oc delete`, `oc create`, or `make deploy/install` command that modifies cluster resources.** These are expected cluster operations — run them directly. Only ask for confirmation at phase-level decision points (e.g. "run e2e tests?", "clean up cluster?").
- The e2e test framework creates its own namespace (`osdk-e2e-*`), deploys the operator there, and cleans up after itself on success. On failure, leftover resources must be cleaned manually (Phase 3a).
- For manual verification (Phase 5), always use `make deploy IMG=<image>` to deploy the operator — never `make e2e-deployment`, which tears down after tests.
- Pod names in `oc run` must be unique — use incrementing suffixes (`metrics-check-1`, `metrics-check-2`, etc.).
- Always include `--image=registry.fedoraproject.org/fedora-minimal:latest` in `oc run` commands.
- When running long commands (e2e tests), use background execution and monitor output.
- Do NOT delete ClusterRoles that belong to other operators (e.g. `machine-api-controllers-metal3-remediation`). Only delete ones created by the compliance-operator e2e framework.
