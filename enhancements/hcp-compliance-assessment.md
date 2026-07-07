---
title: hcp-compliance-assessment
authors:
  - "@ashimpi"
reviewers:
  - "@compliance-operator-maintainers, for overall design review"
  - "@hypershift-team, for HCP architecture validation"
approvers:
  - TBD
api-approvers:
  - None
creation-date: 2026-07-07
last-updated: 2026-07-07
tracking-link:
  - https://redhat.atlassian.net/browse/RFE-9086
see-also:
  - "/doc/usage.md#how-to-use-compliance-operator-with-hypershift-management-cluster"
replaces: []
superseded-by: []
---

# HCP Compliance Assessment Enhancement

## Summary

This enhancement improves the compliance assessment experience for Hosted Control Planes (HCP/HyperShift) 
by introducing HCP-aware default configurations, simplified setup workflows, and enhanced documentation. 
The goal is to achieve feature parity in compliance visibility between traditional OpenShift clusters and 
HCP deployments.

## Motivation

Customers deploying Hosted Control Planes require the same level of compliance assessment and reporting 
capabilities as traditional OpenShift clusters. While the compliance-operator already supports HCP 
environments, the current workflow requires manual configuration of TailoredProfiles and separate 
management of control plane vs. worker node compliance.

Key customer requirements from RFE-9086:
- Compliance assessment of Hosted Control Planes
- Evaluation against standard benchmarks (CIS or custom policies)
- Visibility into compliance posture
- Generation of compliance reports

### Goals

1. **Simplify HCP compliance setup**: Reduce manual configuration required to scan HCP environments
2. **Provide HCP-specific default profiles**: Create ready-to-use profiles for HCP CIS compliance
3. **Improve documentation**: Comprehensive guide for HCP compliance workflows
4. **Add HCP detection helpers**: Automatic detection and configuration for HCP environments

### Non-Goals

1. Unified single-pane compliance dashboard (would require significant UI work)
2. Cross-cluster compliance aggregation (requires multi-cluster architecture changes)
3. Real-time control plane component scanning from hosted cluster (architectural limitation)

## Proposal

### Overview

This enhancement introduces:

1. **HCP-aware ScanSettings**: New default ScanSettings optimized for HCP environments
2. **Pre-built HCP TailoredProfiles**: Ready-to-use profiles for common HCP compliance scenarios
3. **HCP detection utilities**: Helper functions to simplify HCP-specific configurations
4. **Enhanced documentation**: Step-by-step guides for HCP compliance assessment

### User Stories

#### Story 1: Platform Administrator Scanning HCP Control Plane

As a platform administrator managing multiple Hosted Clusters, I want to easily assess the compliance 
posture of my HCP control planes against CIS benchmarks without manually creating TailoredProfiles 
for each cluster.

**Acceptance Criteria**:
- Default HCP-aware ScanSettings are available after operator installation
- Pre-built TailoredProfiles for CIS scanning of HCP control planes
- Documentation on how to use these defaults

#### Story 2: Cluster Administrator Scanning Hosted Cluster Workers

As a cluster administrator of a Hosted Cluster, I want the compliance operator to automatically 
detect the HCP environment and configure scanning appropriately.

**Acceptance Criteria**:
- Automatic detection of HCP environment via ControlPlaneTopology
- Appropriate default roles (worker only) automatically selected
- Clear status indication that control plane scanning requires management cluster setup

### API Extensions

No new CRDs are introduced. This enhancement extends existing behavior through:

1. New default ScanSettings for HCP environments
2. Pre-built TailoredProfile examples in the deployment manifests
3. Enhanced status messages indicating HCP-specific limitations

### Implementation Details/Notes/Constraints

#### 1. HCP-Aware Default ScanSettings

Create a new default ScanSettings specifically for HCP Management Cluster scanning:

```yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: ScanSetting
metadata:
  name: hcp-management-cluster
  namespace: openshift-compliance
spec:
  schedule: "0 1 * * *"
  roles: []  # Platform scans only
  scanType: Platform
  rawResultStorage:
    size: 1Gi
    rotation: 3
```

#### 2. Pre-built HCP TailoredProfile Templates

Provide ConfigMap-based templates that users can customize:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: hcp-tailored-profile-template
  namespace: openshift-compliance
data:
  template.yaml: |
    apiVersion: compliance.openshift.io/v1alpha1
    kind: TailoredProfile
    metadata:
      name: cis-compliance-hcp-CLUSTER_NAME
      namespace: openshift-compliance
      annotations:
        compliance.openshift.io/product-type: Platform
    spec:
      title: CIS Benchmark for HCP - CLUSTER_NAME
      description: CIS Benchmark for HCP control plane components
      extends: ocp4-cis
      setValues:
        - name: ocp4-hypershift-cluster
          value: "CLUSTER_NAME"
          rationale: Target Hosted Cluster name
        - name: ocp4-hypershift-namespace-prefix
          value: "NAMESPACE_PREFIX"
          rationale: Hosted Cluster namespace prefix
```

#### 3. Enhanced Platform Detection

Extend `pkg/utils/platform.go` to provide more HCP context:

```go
// GetHCPInfo returns information about the HCP environment
type HCPInfo struct {
    IsHCP                 bool
    ControlPlaneTopology  string
    ManagementClusterHint string
}

func GetHCPInfo() HCPInfo {
    topology := GetControlPlaneTopology()
    return HCPInfo{
        IsHCP:                IsHostedControlPlane(),
        ControlPlaneTopology: topology,
    }
}
```

#### 4. Improved Status Messages

Add HCP-specific status annotations to ComplianceScan results:

```go
const (
    HCPComplianceNoteAnnotation = "compliance.openshift.io/hcp-note"
)

// When running on hosted cluster, add annotation:
// "Control plane compliance must be assessed from the management cluster. 
//  See documentation for HCP compliance setup."
```

### Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Users may expect unified compliance view | Clear documentation explaining HCP architecture limitations |
| Template customization errors | Validation in operator and helpful error messages |
| Confusion between management/hosted cluster scanning | Clear naming conventions and documentation |

## Design Details

### Open Questions

1. Should we create a CLI tool to generate TailoredProfiles for specific hosted clusters?
2. Should ComplianceSuite status include a field indicating HCP environment?

### Test Plan

1. **Unit Tests**: 
   - HCP detection functions
   - Default ScanSettings creation for HCP
   - Status annotation handling

2. **Integration Tests**:
   - Deploy on HyperShift Management Cluster
   - Verify TailoredProfile templates work correctly
   - Validate scanning of hosted cluster control plane

3. **E2E Tests**:
   - Full compliance workflow on HCP environment
   - Verify results are correctly attributed to hosted cluster

### Upgrade / Downgrade Strategy

- New ScanSettings and ConfigMaps are additive; no impact on existing configurations
- Existing HCP workflows continue to work unchanged
- Users can opt-in to new defaults

### Version Skew Strategy

No version skew concerns as changes are additive configuration defaults.

## Implementation History

- 2026-07-07: Initial enhancement proposal

## Drawbacks

- Additional maintenance burden for HCP-specific defaults
- May create confusion if not well documented

## Alternatives

### Alternative 1: Unified Compliance Controller

Create a new controller that runs on management cluster and automatically discovers/scans 
all hosted clusters. Rejected because:
- Significantly more complex implementation
- Requires cross-cluster RBAC setup
- Out of scope for initial improvement

### Alternative 2: No Enhancement

Keep current manual TailoredProfile workflow. Rejected because:
- Customer feedback indicates setup complexity is a barrier
- RFE-9086 specifically requests easier compliance setup

## Infrastructure Needed

None - uses existing compliance-operator infrastructure.
