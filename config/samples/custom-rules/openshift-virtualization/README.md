# OpenShift Virtualization Hardening with `CustomRule`

The Compliance Operator (version 1.8.0 and newer) includes a `CustomRule`
Custom Resource Definition (CRD). This feature allows you to write your own
compliance checks.

This collection of samples demonstrates how to use `CustomRule` to harden an
OpenShift Virtualization cluster.

## Running a Scan

The following command applies all the `CustomRule` resources in this directory,
bundles them into a `TailoredProfile`, and immediately starts a compliance
scan:

```bash
$ oc apply -k config/samples/custom-rules/openshift-virtualization
```

This scan will produce `ComplianceCheckResult` resources, one for each rule.
You can monitor the progress of the scan and view the results using this
command:

```bash
$ oc get suites,scans,compliancecheckresults
```

The `kustomization.yaml` file in this directory contains the full workflow
using the rules, profiles, bindings, and permissions for the Compliance
Operator to execute these checks.
