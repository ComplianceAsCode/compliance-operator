# Writing and Running CEL Rules in Compliance Operator

## Step 1: Install the Compliance Operator

To use CEL (Common Expression Language) rules, first deploy the Compliance Operator with CEL support. You can check out this demo PR and run:

```sh
make deploy-local
```

This will deploy the Compliance Operator with CEL support in your local environment.

---

## Step 2: Create Custom CEL Rules

You can use the sample rule from `cel-demo/01-custom-rule-cel.yaml` or write your own.

### How to Write a Custom CEL Rule

To create your own rule, follow this template:

1. Define **what resources** you want to evaluate.
2. Specify these resources in the **inputs** section.
3. Write a **CEL expression** that references those resources.

Here’s an example:

```yaml
kind: CustomRule
apiVersion: compliance.openshift.io/v1alpha1
metadata:
  name: custom-rule-example
  namespace: openshift-compliance
spec:
  rationale: "Ensuring compliance with a CEL rule"
  checkType: Platform
  instructions: "Check if the non-root feature gate is enabled"
  title: Ensure Non-Root Feature Gate is Enabled
  scannerType: CEL
  id: content_rule_cel_check
  description: "Use CEL to verify compliance"
  severity: high
  expression: >
    hco.spec.featureGates.nonRoot == true
  inputs:
    - name: hco
      apiGroup: hco.kubevirt.io
      type: KubeGroupVersionResource
      version: v1beta1
      resource: hyperconverged/kubevirt-hyperconverged
      namespace: openshift-cnv
  errorMessage: "Feature gate 'nonRoot' is not enabled"
```

 **Tip:** The `inputs` section defines the API resource being evaluated. You can reference these resources in the CEL expression using the names defined in the input.

### Apply a Custom Rule

If you want to test the demo rule, apply it to your cluster with:

```sh
oc apply -f cel-demo/01-custom-rule-cel.yaml
```

---

## Step 3: Apply Tailored Profile & Scan Setting Binding

To execute your custom CEL rule, reference it in a **TailoredProfile** and create a **ScanSettingBinding**.

Predefined configurations are available in `cel-demo/02-tp.yaml` and `cel-demo/03-ssb.yaml`. Apply them with:

```sh
oc apply -f cel-demo/02-tp.yaml
oc apply -f cel-demo/03-ssb.yaml
```

Alternatively, run everything at once using the provided script:

```sh
cel-demo/run-all.sh
```

---

## Step 4: Run the Scan and Verify Results

The scan should complete in a few seconds! Check the results using:

```sh
oc get ccr | grep custom
```

Example output:

```
custom-rule-configure-network-policies-namespaces-cel   FAIL     high
custom-rule-enable-nonroot-feature-gate-cel             FAIL     high
custom-rule-etcd-cert-file-cel                          PASS     medium
```

You can also check the scan status:

```sh
oc get scan
```

Example output:

```
NAME             PHASE   RESULT
cel-scanner-tp   DONE    NON-COMPLIANT
```

