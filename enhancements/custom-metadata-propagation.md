---
title: custom-metadata-propagation
authors:
  - Vincent056
reviewers:
  - TBD
approvers:
  - TBD
api-approvers: None
creation-date: 2026-02-24
last-updated: 2026-02-24
tracking-link:
  - TBD
---

# Custom Metadata Propagation from Rules to ComplianceCheckResults

## Summary

Allow user-defined labels and annotations on `ComplianceRule` and `CustomRule`
objects to be automatically propagated to the corresponding
`ComplianceCheckResult` objects generated during compliance scans. Additionally,
preserve user-defined annotations on `Rule` objects across ProfileBundle content
updates so that custom metadata is not silently discarded.

## Motivation

Customers need to attach business-specific metadata (e.g., internal severity
ratings, ticket identifiers, audit references) to compliance check results so
that downstream tooling and dashboards can consume it. Today, custom
labels/annotations added to a `ComplianceRule` or `CustomRule` are not carried
forward to the `ComplianceCheckResult`, forcing users to maintain a separate
out-of-band mapping or post-process results with external scripts.

A secondary problem is that user-added annotations on `Rule` objects are
silently overwritten when the profileparser updates Rules during a ProfileBundle
content refresh. This makes it unreliable to use annotations as the carrier for
custom metadata on OpenSCAP-backed Rules.

### Goals

1. Custom (non-operator-managed) labels and annotations on a `Rule` or
   `CustomRule` object are copied to every `ComplianceCheckResult` generated
   from that rule.
2. Operator-managed labels/annotations (prefixed with `compliance.openshift.io/`,
   `complianceoperator.openshift.io/`, `complianceascode.io/`) are never
   overridden by user values.
3. User-added annotations on `Rule` objects survive ProfileBundle content
   updates (profileparser no longer does a full annotation replacement).
4. The feature works for both scan paths: OpenSCAP (aggregator) and CEL scanner.
5. The feature is non-breaking — clusters with no custom metadata on Rules
   see no behavioral change.

### Non-Goals

- Propagating custom metadata from `TailoredProfile` or `ScanSettingBinding`
  objects to results. Those resources are orchestration-level and do not map
  one-to-one to individual check results.
- Providing a UI or CLI for managing custom metadata. Users apply metadata
  via standard `oc label` / `oc annotate` commands.
- Propagating metadata to `ComplianceRemediation` objects (can be addressed
  in a follow-up enhancement).

## Proposal

### User Stories

**Story 1 — Business identifiers on results**
As a compliance engineer, I label a `Rule` with `business-unit: payments` and
annotate it with `internal-id: SEC-4021`. After the scan completes, I can
filter `ComplianceCheckResults` by `business-unit=payments` and find
`internal-id: SEC-4021` in its annotations, without any post-processing.

**Story 2 — Custom severity on CEL rules**
As a platform team lead, I create a `CustomRule` with labels
`break_severity: critical` and `weakness_score: 9.5`. After the CEL scan
runs, the resulting `ComplianceCheckResult` carries both labels so that our
monitoring dashboards can alert on critical findings.

**Story 3 — Metadata survives content updates**
As a cluster admin, I annotate a `Rule` with `exception-ticket: JIRA-123`.
When the ProfileBundle content image is updated, the `Rule` is refreshed but
my `exception-ticket` annotation is preserved, and subsequent scan results
continue to carry it.

### Usage Examples

#### Example 1 — Labeling an OpenSCAP Rule and querying results

```bash
# Add custom labels and annotations to an existing Rule
oc label rule ocp4-api-server-encryption-provider-config \
  business-unit=payments \
  risk-tier=critical \
  -n openshift-compliance

oc annotate rule ocp4-api-server-encryption-provider-config \
  internal-id=SEC-4021 \
  exception-ticket=JIRA-123 \
  -n openshift-compliance

# Trigger a scan (or wait for the next scheduled scan)
oc annotate compliancescan ocp4-cis \
  compliance.openshift.io/rescan= \
  -n openshift-compliance

# After the scan completes, query results by custom label
oc get compliancecheckresults \
  -l business-unit=payments \
  -n openshift-compliance

# Inspect the custom annotations on a specific result
oc get compliancecheckresult \
  ocp4-cis-api-server-encryption-provider-config \
  -o jsonpath='{.metadata.annotations.internal-id}' \
  -n openshift-compliance
# Output: SEC-4021
```

#### Example 2 — CustomRule with metadata for CEL scans

```yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: CustomRule
metadata:
  name: check-pod-security-standard
  namespace: openshift-compliance
  labels:
    break_severity: critical
    weakness_score: "9.5"
  annotations:
    internal-id: SEC-5500
    audit-contact: platform-security-team
spec:
  id: check-pod-security-standard
  title: "Ensure Pod Security Standards are enforced"
  severity: high
  checkType: Platform
  scannerType: CEL
  expression: |
    namespaces.items.all(ns,
      has(ns.metadata.labels) &&
      "pod-security.kubernetes.io/enforce" in ns.metadata.labels
    )
  failureReason: "One or more namespaces do not enforce Pod Security Standards"
  inputs:
    - name: namespaces
      kubernetesInputSpec:
        apiVersion: v1
        resource: namespaces
---
apiVersion: compliance.openshift.io/v1alpha1
kind: TailoredProfile
metadata:
  name: custom-cel-profile
  namespace: openshift-compliance
spec:
  title: "Custom CEL Profile"
  description: "Profile with custom CEL rules"
  enableRules:
    - name: check-pod-security-standard
      rationale: "Enforce pod security standards"
      kind: CustomRule
```

After the CEL scan runs:

```bash
# The ComplianceCheckResult inherits the custom labels
oc get compliancecheckresults \
  -l break_severity=critical \
  -n openshift-compliance

# And the custom annotations
oc get compliancecheckresult \
  custom-cel-profile-check-pod-security-standard \
  -o jsonpath='{.metadata.annotations.internal-id}' \
  -n openshift-compliance
# Output: SEC-5500
```

#### Example 3 — Metadata preserved across content updates

```bash
# Add a custom annotation to a Rule
oc annotate rule ocp4-accounts-restrict-service-account-tokens \
  exception-ticket=JIRA-456 \
  -n openshift-compliance

# Later, the ProfileBundle content image is updated
oc patch profilebundle ocp4 \
  --type merge \
  -p '{"spec":{"contentImage":"registry.example.com/compliance-content:latest"}}' \
  -n openshift-compliance

# After the profileparser re-runs, the custom annotation is preserved
oc get rule ocp4-accounts-restrict-service-account-tokens \
  -o jsonpath='{.metadata.annotations.exception-ticket}' \
  -n openshift-compliance
# Output: JIRA-456
```

### API Extensions

No new CRDs or API fields are introduced. The enhancement uses the existing
Kubernetes `ObjectMeta.Labels` and `ObjectMeta.Annotations` on `Rule`,
`CustomRule`, and `ComplianceCheckResult` resources.

### Implementation Details

The implementation spans three components:

#### Component 1 — Utility library (`pkg/utils/rule_metadata.go`)

A new file providing:

| Function / Type | Purpose |
|---|---|
| `IsOperatorManagedKey(key)` | Returns `true` if the key starts with a known operator prefix. |
| `GetCustomMetadata(labels, annotations)` | Filters out operator-managed keys, returning only custom entries. |
| `RuleMetadataCache` | Indexes all `Rule` objects in a namespace by their `compliance.openshift.io/rule` annotation value, caching their custom labels and annotations. Built once per aggregation run. |
| `NewRuleMetadataCache(client, namespace)` | Lists all Rules, extracts custom metadata, populates cache. |
| `GetCustomMetadataForRule(ruleDNSName)` | Cache lookup. Returns `nil, nil` for unknown rules or nil receiver. |
| `MergeCustomMetadata(targetLabels, customLabels, targetAnnotations, customAnnotations)` | Adds custom entries to target maps only when the key does not already exist (operator entries take precedence). |

Operator-managed prefixes:
- `compliance.openshift.io/`
- `complianceoperator.openshift.io/`
- `complianceascode.io/`

#### Component 2 — OpenSCAP aggregator path (`cmd/manager/aggregator.go`)

In `createResults()`, after building the standard check-result labels and
annotations, the aggregator:

1. Builds a `RuleMetadataCache` (one API call to list all Rules in the
   namespace). Failure is non-fatal; a warning is logged and propagation is
   skipped.
2. For each result, converts the XCCDF rule ID to a DNS-friendly name via
   `IDToDNSFriendlyName()` and looks up custom metadata from the cache.
3. Merges custom metadata into the check-result labels and annotations via
   `MergeCustomMetadata()`.

```
createResults()
  ├── NewRuleMetadataCache(client, namespace)   // one List call
  └── for each result:
        ├── getCheckResultLabels()              // operator labels
        ├── getCheckResultAnnotations()         // operator annotations
        ├── ruleDNSName = IDToDNSFriendlyName(result.ID)
        ├── cache.GetCustomMetadataForRule(ruleDNSName)
        ├── MergeCustomMetadata(labels, custom, annotations, custom)
        └── createOrUpdateOneResult()
```

#### Component 3 — CEL scanner path (`cmd/manager/cel-scanner.go`)

In `runPlatformScan()`, when building the `ComplianceCheckResult` from a
`CustomRule` evaluation:

1. Call `GetCustomMetadata(originalRule.GetLabels(), originalRule.GetAnnotations())`
   to extract non-operator metadata directly from the `CustomRule` object.
2. Set the custom labels and annotations on the `ComplianceCheckResult`
   `ObjectMeta` before it enters the standard label/annotation assembly.

The existing `getCheckResultLabels()` and `getCheckResultAnnotations()` functions
receive `pr.Labels` and `pr.Annotations`, which now include the custom entries.
Because those functions merge `resultLabels` into a new map that already contains
operator labels, operator values always win (set first), and custom values are
appended.

#### Component 4 — Profileparser annotation preservation (`pkg/profileparser/profileparser.go`)

**Current behavior (bug):** The Rule update callback does a full replacement:
```go
foundRule.Annotations = updatedRule.Annotations
```
This discards any user-added annotations.

**New behavior:** Merge operator-managed and content-derived annotations from the
parser into the existing annotation map, preserving user-added keys:

```go
for k, v := range updatedRule.Annotations {
    foundRule.Annotations[k] = v
}
```

This ensures that:
- All parser-managed annotations (rule ID, image digest, profiles, control
  references) are updated to current values.
- User-added annotations (keys not set by the parser) survive the update.

Labels are already preserved by the current code (the update callback does not
touch `foundRule.Labels`), so no change is needed for labels.

### Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Extra API call to list Rules during aggregation | Single List call cached for the entire run. Rule counts are O(hundreds), well within API server capacity. |
| Kubernetes label value validation failures from user input | Labels have a 63-character value limit. Invalid values will cause the `ComplianceCheckResult` create/update to fail for that specific result. The aggregator logs the error and continues. Users should prefer annotations for long or free-form values. |
| Stale cache if Rules are modified mid-scan | Acceptable: scans are point-in-time. The cache reflects the state at aggregation start. |
| User annotations accumulate unboundedly on Rules | Out of scope — standard Kubernetes resource hygiene. The operator only copies what exists, it does not generate new keys. |
| Annotation preservation may keep obsolete user keys | This is the desired behavior. Users manage their own keys via `oc annotate --overwrite` or removal. |

## Design Details

### Open Questions

1. Should the operator also propagate custom metadata to
   `ComplianceRemediation` objects? (Deferred to follow-up.)
2. Should there be a maximum number of custom labels/annotations propagated
   to prevent abuse? (Current proposal: no limit, rely on Kubernetes native
   validation.)

### Test Plan

**Unit tests** (`pkg/utils/rule_metadata_test.go`):
- `TestIsOperatorManagedKey` — Operator-managed vs custom key classification.
- `TestGetCustomMetadata` — Extraction with mixed, nil, all-custom, no-custom inputs.
- `TestMergeCustomMetadata` — Merge into existing maps, nil maps, no-overwrite behavior.
- `TestNewRuleMetadataCache` — Cache building and lookup with fake client.
- `TestRuleMetadataCacheIntegration` — End-to-end: Rule with custom metadata →
  cache → lookup by DNS name → merge into check-result maps.

**Unit tests** (`pkg/profileparser/profileparser_test.go`):
- Verify that updating a Rule preserves user-added annotations while
  refreshing operator-managed annotations.

**E2E tests**:
- Create a `Rule` with custom labels/annotations. Run a scan. Verify the
  corresponding `ComplianceCheckResult` carries the custom metadata.
- Create a `CustomRule` with custom labels/annotations. Run a CEL scan.
  Verify the corresponding `ComplianceCheckResult` carries the custom metadata.
- Update the ProfileBundle content image. Verify that user-added annotations
  on `Rule` objects are preserved after the profileparser re-runs.
- Verify that operator-managed labels/annotations on `ComplianceCheckResult`
  are never overridden by user values with the same key prefix.

### Upgrade Strategy

No migration needed. The feature is purely additive. Existing clusters with no
custom metadata on Rules see no change — `GetCustomMetadata()` returns
`nil, nil` and the merge is a no-op.

### Version Skew Strategy

All changes are within the compliance-operator; there is no cross-component
version skew concern. The aggregator and CEL scanner run in pods managed by the
operator's own Deployment and DaemonSet, so they are always at the same version
as the operator controller.

### Operational Aspects of API Extensions

No new API extensions are introduced. The enhancement adds labels/annotations
to existing `ComplianceCheckResult` resources, which has negligible impact on
API throughput or etcd storage (a few extra key-value pairs per result object).

#### Failure Modes

- **RuleMetadataCache build failure:** Logged as a warning. Scan results are
  still created, just without custom metadata. No operator degradation.
- **Invalid label value on ComplianceCheckResult:** The specific result
  create/update fails. The aggregator logs the error and continues with
  remaining results.

#### Support Procedures

- Check operator logs for `"could not build rule metadata cache"` to diagnose
  propagation failures.
- Verify custom metadata on Rule objects: `oc get rule <name> -o yaml` and
  confirm non-operator-prefixed labels/annotations exist.
- Verify propagation: `oc get compliancecheckresult -l <custom-label>=<value>`.

## Implementation History

## Drawbacks

- Slightly increases the size of `ComplianceCheckResult` objects in etcd when
  users attach custom metadata. This is bounded by what users explicitly add
  and is consistent with standard Kubernetes metadata patterns.
- The profileparser annotation-merge change is a subtle behavioral shift that
  could theoretically preserve annotations users intended to remove. However,
  the removal path (`oc annotate rule <name> key-`) remains fully
  functional and is the standard Kubernetes pattern.

## Alternatives

1. **Dedicated `customMetadata` field on the CRD spec:** Would require a CRD
   schema change and API review. Labels/annotations are the idiomatic
   Kubernetes mechanism for user-attached metadata and require no schema
   changes.

2. **External annotation controller:** A separate controller could watch Rules
   and patch ComplianceCheckResults. This adds operational complexity and
   introduces race conditions with the aggregator.

3. **TailoredProfile-level metadata:** Metadata defined at the TailoredProfile
   level would apply uniformly to all rules in the profile, which does not
   satisfy the per-rule granularity requirement.

## Infrastructure Needed

None.
