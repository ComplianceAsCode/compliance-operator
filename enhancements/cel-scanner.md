# CEL-Based Scanner for Compliance Operator (TechPreview)

## Summary

This enhancement proposes introducing a **new CRD** called `CustomRule` to provide **CEL** (Common Expression Language) scanning capabilities in the Compliance Operator. By creating a stand-alone CRD, instead of modifying the existing `ComplianceScan` resource, we preserve backward compatibility for the OpenSCAP-based workflows.

Furthermore, we will **merge** the functionalities of the *API resource collector*, *CEL scanner*, and *log-collector* into a **single container** (the “cel-scanner”). This consolidation means that each scan job runs as a single Pod that:

1. **Fetches** the relevant Kubernetes objects (rather than using a separate `api-resource-collector` container).  
2. **Evaluates** them against the `CustomRule`’s CEL expression(s).  
3. **Produces** the results and stores them in a `ConfigMap` for the aggregator to consume (rather than running a separate `log-collector` container).  

By doing so, we reduce overhead and complexity (fewer containers), making the new CEL-based scanning approach more streamlined while leaving the existing OpenSCAP-based flow untouched.

## Motivation

### Background

The Compliance Operator currently relies on `oscap`. Developing compliance checks is a complex process requiring:

- Deep SCAP and OVAL knowledge.
- Familiarity with the SCAP content build system.
- Time-consuming cycles for building containers, uploading them to the cluster, and awaiting parsing to validate rule functionality.

### Why CEL?

- CEL is already popular and widely used throughout the Kubernetes community, thus **reducing the learning curve**.
- It integrates with typical cluster-admin workflows; writing or editing a CEL rule is more straightforward than SCAP/OVAL content.
- We already have a proof-of-concept (POC) that integrates CEL scanning with the Compliance Operator. 

### Key Benefits

1. **Backward Compatibility**  
   - Users relying on existing SCAP-based scans (`ComplianceScan`) see no difference.  
   - We do **not** add new fields to `ComplianceScan`; instead, we introduce a new CRD for CEL-based scanning.

2. **Simplified Architecture**  
   - A single container (the “cel-scanner”) handles *resource fetching*, *rule evaluation*, and *result upload (ConfigMap creation)*.  
   - **No** need to coordinate multiple pods or containers for scanning/log-collection tasks.

3. **Custom Checks**  
   - Allows teams to define **lightweight** checks in a simpler manner using CEL expressions.

4. **Flexible Implementation**  
   - By creating a new `CustomRule` CRD, we can evolve the CEL-based scanning logic independently without disrupting OpenSCAP scanning.

## Goals

- Provide a new custom scanning flow via a `CustomRule` CRD that supports:
  - **CEL Expressions** referencing arbitrary Kubernetes resources.
  - Direct references to resources to be fetched and evaluated.
- Consolidate the `api-resource-collector`, `scanner`, and `log-collector` into **one container** to streamline the scanning pipeline:
  - **Re-use** existing collector logic where possible (in-process).
  - **Create ConfigMaps** directly from the CEL scanner (no separate logging container).
- **Remove** `cmd/manager/resultcollector.go` for CEL scans (since no ARF report is generated).
- Keep minimal or **no changes** to existing CRDs for SCAP, to maintain full backward compatibility with OpenSCAP.

## Non-Goals

- **Node-based scanning** with CEL (only cluster objects are targeted initially).
- **Auto-remediation** for CEL checks (no automated fix logic).
- **ProfileBundle** import for CEL content (`CustomRule` is manually defined, not derived from SCAP data streams).

## Proposal

### 1. New CRD: `CustomRule`

We introduce a new type, `CustomRule`, that extends from the existing `ComplianceRule` concept. The additional fields (highlighted below) support CEL expressions:

```yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: CustomRule
metadata:
  name: example-customrule
spec:
  # Existing fields in compliance rule
  id: "my_cel_rule_example"
  title: "Ensure that application Namespaces have Network Policies defined"
  severity: "high"

  # New CEL-specific fields
  expression: |
    size(nl.items) == 0 || ...
  inputs:
    - name: nl
      apiGroup: ""
      version: v1
      resource: namespaces
    - name: npl
      apiGroup: networking.k8s.io
      version: v1
      resource: networkpolicies
  errorMessage: "Application Namespaces do not have a NetworkPolicy."
```

- `expression`: The CEL expression to be evaluated.
- `inputs`: A list of resource references the scanner must fetch from the cluster before evaluation.
- `errorMessage`: Shown if the CEL expression evaluates to false.

Additionally, the `scannerType` defaults to **`cel`** so that future scanners can be added without changing the CRD again.

### 2. Single Pod/Container Flow

#### a) “CEL Scanner” Pod

When referencing `CustomRule` objects (e.g., in a `TailoredProfile`), a new **cel-scanner** Pod is launched. This single container will:

1. **Discover** which `CustomRule` objects to evaluate.  
2. **Fetch** the relevant resources (from `inputs`).  
3. **Evaluate** the CEL expression(s).  
4. **Write** results (pass/fail) into a JSON structure, alongside rule info.  
5. **Create** a `ConfigMap` that holds the JSON results and any warnings.

#### b) Merged Collector and Logger

Previously, separate containers existed for `api-resource-collector`, `cel-scanner`, and `log-collector`. Now:

- **All** fetching, evaluating, and `ConfigMap` creation is done *in one process* (`cel-scanner`).  
- **No** additional container is needed to collect logs or store them in a `ConfigMap`.  

**ConfigMap Generation**  
After evaluation, the container immediately writes results to a `ConfigMap` (for example, `<compliance-cel-scan>-results`). It includes a small JSON payload indicating pass/fail per rule. The aggregator picks up these `ConfigMaps` exactly like it does for OpenSCAP scans.

### 3. Aggregation Flow

- The aggregator detects “CEL-based results” by annotation or other metadata in the `ConfigMap`.
- Converts the JSON results into `ComplianceCheckResult` objects (looking up metadata from the corresponding `CustomRule` CR).  
- As a result, `oc get ccr` commands continue to display PASS/FAIL for these custom rules.

### 4. Interaction with `TailoredProfile`

`TailoredProfile` can be extended to reference `CustomRule` objects:

```yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: TailoredProfile
metadata:
  name: custom-cel-profile
spec:
  enableRules:
    - name: example-customrule
      type: CustomRule
      rationale: "We want to ensure all namespaces have a NetworkPolicy."
```

- The `type` differentiates `CustomRule` from the classical `ComplianceRule`.
- The `ScanSettingBinding` picks up the `TailoredProfile`.  
- The operator sees the presence of `CustomRule` references and launches a CEL-based scanner Pod.

**Implementation Outline**  
- `TailoredProfile` controller examines if the profile references any `CustomRule`. It sets an annotation on the `TailoredProfile` indicating **cel** scanning.  
- `ScanSettingBinding` detects that annotation and configures a `ComplianceScanSpec` object with `scannerType: cel`.  
- The `ComplianceScan` controller (or an equivalent scanning workflow) launches the single **cel-scanner** Pod.

### User Stories

1. **On the fly Custom Rule ComplianceCheck**
   An admin wants to confirm each non-control-plane namespace has at least one `NetworkPolicy`. They define a `CustomRule` referencing `namespaces` and `networkpolicies`.  
   - The “cel-scanner” container fetches these resources, checks the CEL expression, and evaulate to a pass/fail turns this into a `ComplianceCheckResult`.

### API Extensions

- **`CustomRule` CRD**:  
  - A new CRD Extends existing `ComplianceRule` logic with CEL-specific fields.  

- **`TailoredProfile` CRD**:  
  - Add Type filed in Spec.enableRules 
  - Extended to reference `CustomRule` objects under `enableRules[]`.  
  - Sets a `scannerType` annotation if only `CustomRule`s are enabled.

- **`ComplianceScan` CRD**:  
  - Add new field `scannerType` in Spec

### Implementation Details / Notes / Constraints

- **RBAC**: The “cel-scanner” Pod needs read permissions (`get/list/watch`) for every resource type mentioned in the `inputs`.
- **Performance**: Large-scale resource fetching can be costly if a `CustomRule` references a wide resource scope.

### Risks and Mitigations

- **Excessive Resource Fetching**: Large queries can slow the cluster. Mitigate by documenting best practices (narrow `namespace`, etc.).  
- **Security**: Broad `get/list/watch` for multiple resource types. Admins can carefully scope or block unneeded RBAC for `CustomRule`s.

## Design Details

### Test Plan

1. **Unit Tests**  
   - Validate `CustomRule` fields (e.g., `inputs`, `expression`).
   - Test parsing and evaluating CEL expressions.

2. **End-to-End Tests**  
   - Deploy operator.  
   - Create one or more `CustomRule`s.  
   - Create `TailoredProfile` referencing these `CustomRule`s.  
   - Confirm the single “cel-scanner” Pod runs, collects resources, and produces a `ConfigMap`.  
   - Verify aggregator transforms it into `ComplianceCheckResult`.

3. **Load / Scale Tests**  
   - Evaluate performance with large sets of cluster resources or numerous `CustomRule`s.

### Upgrade / Downgrade Strategy

- This is a **TechPreview** feature. The `CustomRule` CRD may evolve over time.  
- Existing `ComplianceScan` functionality is **unchanged**; users can selectively adopt CEL scanning.

### Failure Modes

- The “cel-scanner” might fail to create the results `ConfigMap` or run out of memory. Logs will indicate the cause.
- If aggregator doesn’t parse the new result type, no `CCR` is created.

### Support Procedures

- Check the “cel-scanner” Pod logs for errors in resource fetching or CEL evaluation.
- Inspect the aggregator logs if `CCR` objects are not created as expected.
