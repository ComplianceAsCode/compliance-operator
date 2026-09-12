# HCP (Hosted Control Planes) Compliance Samples

This directory contains sample configurations for running compliance scans
on Hosted Control Plane (HCP/HyperShift) environments.

## Overview

HCP compliance scanning has two deployment scenarios:

### 1. Management Cluster Scanning (Control Plane)

Deploy the compliance operator on the **management cluster** to scan the
control plane components of your hosted clusters.

**Files:**
- `tailoredprofile-cis-hcp.yaml` - CIS benchmark for HCP control plane
- `tailoredprofile-pci-dss-hcp.yaml` - PCI-DSS benchmark for HCP control plane
- `scansettingbinding-hcp.yaml` - Binding to run the scan

**Steps:**
1. Install Compliance Operator on the management cluster
2. Edit the TailoredProfile to set your Hosted Cluster name and namespace prefix
3. Apply the TailoredProfile: `oc apply -f tailoredprofile-cis-hcp.yaml`
4. Apply the ScanSettingBinding: `oc apply -f scansettingbinding-hcp.yaml`

### 2. Hosted Cluster Scanning (Worker Nodes)

Deploy the compliance operator on the **hosted cluster** to scan worker nodes.
Note that control plane components cannot be scanned from the hosted cluster.

**Steps:**
1. Use the special subscription with `PLATFORM=HyperShift` environment variable
2. The operator will automatically configure appropriate defaults for worker scanning

See the [main usage documentation](../../../doc/usage.md#how-to-use-compliance-operator-with-hypershift-hosted-cluster)
for detailed instructions.

## Customization

### Scanning Multiple Hosted Clusters

Create a separate TailoredProfile for each hosted cluster:

```bash
# Copy and customize for each hosted cluster
cp tailoredprofile-cis-hcp.yaml tailoredprofile-cis-hcp-cluster1.yaml
# Edit the file to set the correct cluster name and namespace
```

### Custom Scan Schedule

Edit the ScanSettingBinding to reference a custom ScanSetting with your
preferred schedule:

```yaml
settingsRef:
  name: my-custom-scansetting
  kind: ScanSetting
  apiGroup: compliance.openshift.io/v1alpha1
```

## Troubleshooting

### "Profile not found" errors
Ensure the ProfileBundle has finished parsing. Check:
```bash
oc get profilebundles -n openshift-compliance
```

### Rules showing as "NOT-APPLICABLE"
Some rules are not applicable in HCP environments. The operator automatically
hides non-applicable rules based on the platform detection.

### Cannot scan control plane from hosted cluster
This is expected behavior. Control plane components run on the management
cluster and must be scanned from there using a TailoredProfile.
