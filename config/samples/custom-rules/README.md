# Custom Rules (`CustomRule`)

`CustomRule` resources provide a flexible way to define compliance checks using
the [Common Expression Language (CEL)](https://github.com/google/cel-spec) in
the Compliance Operator. They allow you to create custom compliance checks
against any resource the Compliance Operator service account has access to via
the Kubernetes API.

A `CustomRule` shares most attributes with `Rule` custom resources definitions:

- `description`: A human-readable explanation of the rule
- `failureReason`: Message displayed when the rule fails
- `expression`: CEL expression to evaluate the compliance condition
- `id`: Unique identifier for the rule
- `checkType`: Type of check (e.g., Platform)
- `inputs`: Kubernetes resources to be evaluated
- `scannerType`: Must be set to CEL
- `severity`: Importance of the rule
- `title`: Short, descriptive name of the rule

The following example is available in
[pods-must-have-security-context.yaml](pods-must-have-security-context.yaml):

```yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: CustomRule
metadata:
  name: pods-must-have-security-context
  namespace: openshift-compliance
spec:
  description: Ensures all pods have a security context defined with runAsNonRoot set to true
  failureReason: Pod(s) found without proper security context (runAsNonRoot must be true)
  expression: |
    pods.items.all(pod,
      pod.spec.securityContext != null &&
      pod.spec.securityContext.runAsNonRoot == true
    )
  id: pods_must_have_security_context
  checkType: Platform
  inputs:
    - kubernetesInputSpec:
        apiVersion: v1
        resource: pods
      name: pods
  scannerType: CEL
  severity: high
  title: Pods Must Have Security Context
```

Explore additional examples in `config/samples/custom-rules`.

## Using CustomRules with TailoredProfile

To use a `CustomRule` in a scan, you must include it in a `TailoredProfile`:

```yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: TailoredProfile
metadata:
  name: custom-security-checks
  namespace: openshift-compliance
spec:
  description: Custom security compliance profile using CEL-based CustomRules
  enableRules:
    - kind: CustomRule
      name: pods-must-have-security-context
      rationale: Security best practice requires pods to run as non-root
  title: Custom Security Profile
```

Then create a `ScanSettingBinding` to run the scan:

```yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: ScanSettingBinding
metadata:
  name: custom-security-scan
  namespace: openshift-compliance
profiles:
  - apiGroup: compliance.openshift.io/v1alpha1
    kind: TailoredProfile
    name: custom-security-checks
settingsRef:
  apiGroup: compliance.openshift.io/v1alpha1
  kind: ScanSetting
  name: default
```

## Experimenting with CustomRules

To apply the sample `CustomRule` resources, a `TailoredProfile`, and a
`ScanSettingBinding`, use the `oc apply -k config/samples/custom-rules/`
command.

```bash
$ oc apply -k config/samples/custom-rules
customrule.compliance.openshift.io/pods-must-have-security-context created
customrule.compliance.openshift.io/pods-read-only-host-filesystem created
scansettingbinding.compliance.openshift.io/custom-security-checks-binding created
tailoredprofile.compliance.openshift.io/custom-security-checks created
```

This will scan the cluster and produce `ComplianceCheckResult` resources for
each `CustomRule` included in the `TailoredProfile`:

```bash
$ oc get compliancecheckresults
NAME                                                           STATUS   SEVERITY
custom-security-checks-custom-pods-read-only-host-filesystem   FAIL     high
custom-security-checks-pods-must-have-security-context         FAIL     high
```

## Authoring Tips

When writing your own `CustomRule` resources:

* Create rules in the same namespace as the Compliance Operator (`openshift-compliance` by default).
* Write CEL expressions that evaluate to `true` for rules that pass.
* Make your rule `metadata.name` specific (e.g., `pods-must-have-security-context` instead of `pod-rule-1`).
* Use `spec.description` to describe *why* the rule exists, not just what it does.
* Only request the resources you absolutely need for your expression. Fetching unnecessary resources will increase scan time and memory usage.
* Make `spec.failureReason` actionable so readers know what they need to do to be compliant.

## Troubleshooting

If your `CustomRule` or `TailoredProfile` is not working as expected:

1. Make sure the `CustomRule` is in a `Ready` state before including it in a `TailoredProfile`. Invalid CEL expressions will cause the `CustomRule` to go into an `Error` state.
2. Make sure the `TailoredProfile` is also in a `READY` state before referencing it in a `ScanSettingBinding`.
3. Group your rules logically, do not mix `Rule` and `CustomRule` resources in the same `TailoredProfile`.
4. Rerun the scan to update the `ComplianceCheckResult` after making changes to your `CustomRule`.
