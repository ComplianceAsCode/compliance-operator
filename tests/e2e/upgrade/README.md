# Upgrade E2E Test Suite

This test suite validates operator upgrade scenarios using OLM (Operator Lifecycle Manager).

## Purpose

The upgrade suite differs from the parallel and serial suites:
- **Parallel suite**: Installs operator from manifests, runs tests in parallel
- **Serial suite**: Installs operator from manifests, runs tests serially
- **Upgrade suite**: Assumes operator is already installed via OLM, tests upgrade scenarios

## Tests

### TestOperatorUpgradeResourcesAndMCPStability

Validates that compliance operator resources and MachineConfigPool status remain stable during operator upgrades.

**Provides upstream parity for downstream tests:**
- OCP-45014: Precheck and postcheck for compliance operator resources count
- OCP-45956: MachineConfigPool status during operator upgrades

**The test validates:**
1. No resources (rules, variables, profiles) are lost during upgrade
2. MachineConfigPools remain healthy (not degraded, not paused)
3. Detailed diff shows exactly which resources changed (if any)

**Key enhancement over downstream tests:**
- Tracks individual resource names, not just counts
- Shows exactly WHICH resources were added/removed when test fails
- Provides detailed diff output for debugging

## Running the Tests

### Prerequisites

1. **OpenShift cluster** with compliance operator already installed via OLM
2. **Environment variables:**
   - `UPGRADE_CATALOG_SOURCE_IMAGE`: Image URL for the upgrade catalog (e.g., Konflux build)
   - `STARTING_CSV`: Current operator version (optional, auto-detected if already installed)

### Example: Test Upgrade from v1.6.2 to v1.8.2

**For a complete step-by-step guide for fresh clusters, see [../../../UPGRADE_TEST_EXAMPLE.md](../../../UPGRADE_TEST_EXAMPLE.md)**

```bash
# Ensure operator is installed at base version (e.g., v1.6.2)
# This should be done via OLM Subscription

# Set upgrade catalog image (REAL VALUE - Konflux build with all versions)
export UPGRADE_CATALOG_SOURCE_IMAGE="quay.io/redhat-user-workloads/ocp-isc-tenant/compliance-operator-fbc-4-21@sha256:aa74fbf80ffd4d3743161a7c4722806586359a11ce09ce37e80459ffa7b21cb6"

# Set starting CSV (or let test auto-detect)
export STARTING_CSV="compliance-operator.v1.6.2"

# Create dummy manifest files (operator already installed via OLM)
mkdir -p /tmp/co-test-manifests
cat > /tmp/co-test-manifests/empty-namespaced.yaml <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-dummy-ns
data:
  note: "Operator already installed"
EOF

cat > /tmp/co-test-manifests/empty-global.yaml <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-dummy
  namespace: default
data:
  note: "Operator already installed"
EOF

# Run the upgrade test
go test -v -timeout 60m \
  -root="$(pwd)/../../.." \
  -namespacedMan=/tmp/co-test-manifests/empty-namespaced.yaml \
  -globalMan=/tmp/co-test-manifests/empty-global.yaml \
  -run TestOperatorUpgradeResourcesAndMCPStability
```

### What the Test Does

1. **Pre-upgrade checks:**
   - Validates MachineConfigPools (master, worker) are healthy
   - Captures snapshot of all compliance resources with individual names

2. **Performs upgrade:**
   - Creates/uses CatalogSource with upgrade image
   - Patches subscription to trigger upgrade
   - Waits for new InstallPlan and approves it
   - Waits for new CSV to reach Succeeded state

3. **Post-upgrade checks:**
   - Validates MachineConfigPools remain healthy
   - Captures new resource snapshot
   - Compares snapshots with detailed diff

4. **Validation:**
   - Fails if any resources were lost
   - Shows exactly which resources were added/removed
   - Logs success if all checks pass

## Test Output

### Success Example
```
=== PRE-UPGRADE: Checking MachineConfigPool status ===
=== PRE-UPGRADE: Capturing resource snapshot ===
Resource snapshot before upgrade - Rules: 450, Variables: 35, Profiles: 15

=== UPGRADE: Setting up upgrade catalog source ===
✅ CatalogSource compliance-operator-upgrade created
CatalogSource is READY

=== UPGRADE: Patching subscription to trigger upgrade ===
Current CSV: compliance-operator.v1.6.2
Found new InstallPlan: install-abcde for CSV: compliance-operator.v1.8.2
Approving InstallPlan: install-abcde
New CSV compliance-operator.v1.8.2 reached Succeeded phase
✅ Operator upgrade completed successfully!

=== POST-UPGRADE: Checking MachineConfigPool status ===
=== POST-UPGRADE: Capturing resource snapshot ===
Resource snapshot after upgrade - Rules: 455, Variables: 37, Profiles: 16

=== VALIDATION: Comparing resource snapshots ===
Resource changes during upgrade:
Added Rules (5):
  - ocp4-new-rule-1
  - ocp4-new-rule-2
  - rhcos-new-rule-3
  - rhcos-new-rule-4
  - rhcos-new-rule-5
Added Variables (2):
  - var-new-setting-1
  - var-new-setting-2
Added Profiles (1):
  - ocp4-new-profile

New resources were added during upgrade (this is expected)

=== SUCCESS ===
Operator upgrade validation passed:
  ✓ MachineConfigPools remained healthy
  ✓ No resources were lost
  ✓ Resource tracking functions work correctly
```

### Failure Example
```
=== VALIDATION: Comparing resource snapshots ===
UPGRADE VALIDATION FAILED - Resources were lost:
Resources were lost during upgrade: 3 rules, 1 variable, 0 profiles

Detailed diff:
Removed Rules (3):
  - ocp4-old-deprecated-rule
  - rhcos-removed-check
  - rhcos-legacy-rule
Removed Variables (1):
  - var-old-setting

--- FAIL: TestOperatorUpgradeResourcesAndMCPStability (720.45s)
```

## CI/CD Integration

This test suite is designed to be integrated into upgrade testing pipelines:

1. **Pre-requisite**: Cluster with operator installed at base version
2. **Input**: Catalog image with target upgrade version
3. **Output**: Pass/fail with detailed resource diff
4. **Cleanup**: Automatically removes test CatalogSource after test

## Troubleshooting

### Test skipped with "UPGRADE_CATALOG_SOURCE_IMAGE and STARTING_CSV must be set"
- Ensure environment variables are exported before running test
- Or, if operator is already installed, STARTING_CSV can be omitted (auto-detected)

### "No installed CSV found in subscription status"
- Operator must be installed via OLM Subscription before running test
- Check: `oc get subscription -n openshift-compliance`

### "Timeout waiting for CatalogSource to be READY"
- Verify catalog image URL is correct and accessible
- Check: `oc describe catalogsource compliance-operator-upgrade -n openshift-marketplace`

### "Resources were lost during upgrade"
- This indicates a real upgrade issue
- Review the detailed diff to see which specific resources were removed
- Investigate why those resources disappeared during upgrade
