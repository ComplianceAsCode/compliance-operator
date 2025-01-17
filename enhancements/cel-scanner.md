# CEL-Based Scanner for Compliance Operator (TechPreview)

## Summary

This enhancement proposes introducing a **new CRD** called `CustomRule` to provide **CEL** (Common Expression Language) scanning capabilities in the Compliance Operator. By creating a stand-alone CRD, instead of modifying the existing `ComplianceScan` resource, we preserve backward compatibility for the OpenSCAP-based workflows.

Furthermore, we will **merge** the functionalities of the *API resource collector*, *CEL scanner*, and *log-collector* into a **single container** (the “cel-scanner”). This consolidation means that each scan job runs as a single Pod that:

1. **Fetches** the relevant Kubernetes objects (rather than using a separate `api-resource-collector` container).  
2. **Evaluates** them against the `CustomRule`’s CEL expression(s).  
3. **Produces** having the `CEL` scanner to create the `ComplianceCheckResult`directly

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
   - A single container (the “cel-scanner”) handles *resource fetching*, *rule evaluation*, and *result creation*.  
   - **No** need to coordinate multiple pods or containers for scanning/log-collection tasks.

3. **Custom Checks**  
   - Allows teams to define **lightweight** checks in a simpler manner using CEL expressions, make the development cycle of rule much shorter,

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
- **ProfileBundle** import for CEL content (`CustomRule` is manually defined, not derived from SCAP datastreams).

## Proposal


### 1. New CRD: `CustomRule`

We extend the current concept of a compliance **Rule** by allowing a new `CustomRule` resource that specifically supports CEL-based evaluation fields:

```yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: CustomRule
metadata:
  name: example-customrule
spec:
  id: "my_cel_rule_example"
  title: "Ensure that application Namespaces have Network Policies defined"
  severity: "high"
  
  # Cel-specific fields
  scannerType: "cel"
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

**Key Fields**  
- `scannerType`: new enum field set to `"cel"`, this is the only
  option we support with CustomRule
- `expression`: the CEL expression to evaluate.  
- `inputs`: a list describing which K8s resources to fetch prior to running `expression`.  
- `errorMessage`: the message that is displayed if the rule fails.

### 2. Adjusting Existing CRDs

**a) `ComplianceScan`**  
We introduce a new enum field `spec.scannerType`, defaulting to `"openscap"`. Example snippet:

```yaml
spec:
  scanType: "Platform"    # existing field
  scannerType: "cel"      # new field, can be "cel" or "openscap"
```

When `spec.scannerType == "cel"`, the operator will launch the new single “cel-scanner” container logic.

**b) `TailoredProfile`**  
We allow referencing `CustomRule` objects inside `TailoredProfile` the same way as normal `Rule` objects. In `TailoredProfile.spec.enableRules`, each selection can specify a `type: CustomRule` (instead of `Rule`).  

Additionally, we add an annotation to `TailoredProfile` if it only has CEL rules, e.g. `compliance.openshift.io/scanner-type: "cel"`. The `ScanSettingBinding` uses this annotation to decide which scannerType to set on the `ComplianceScan`.

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

We will add validation checks that make sure a `TailoredProfile` only contain rules that belongs to either OpenScap or CEL

**c) `ScanSettingBinding`**  
1. Read the `TailoredProfile` and check its annotation `compliance.openshift.io/scanner-type: "cel"`.
2. If the annotation is `"cel"`, composite the `ComplianceScan` with `spec.scannerType="cel"` for the suite.
3. Otherwise (or by default), use `"openscap"`.



### 3. The “cel-scanner” pod flow

#### 3.1 Pod Creation

- **ComplianceScan Controller** checks `scan.Spec.scannerType`.
  - In `phaseLaunchingHandler` we will detect if `scannerType` is cel we will skip the result server related componetes, since we don't have to save the ARF report
  - During launching phase, we will need to have `PlatformScanTypeHandler` to know what scannerType it is and, create pods differently.
  - If `"openscap"`, it proceeds with the existing `oscap` Pod logic.
  - If `"cel"`, it creates a single Pod with exactly **one container**:
    1. **Resource fetching** (previously `api-resource-collector`)
    2. **Evaluation** (previously separate CEL container)
    3. **ConfigMap / Result writing** (previously `log-collector`)
  - In `phaseAggregatingHandler` we will skip the aggregator pod creating when detect the `scannerType` to be CEL

##### Pseudo-Code: `ReconcileComplianceScan` Snippet

```go
/// existing codes:
func (ph *platformScanTypeHandler) createScanWorkload() error {
	ph.l.Info("Creating a Platform scan pod")
	pod := ph.r.newPlatformScanPod(ph.scan, ph.l)
	if priorityClassExist, why := utils.ValidatePriorityClassExist(ph.scan.Spec.PriorityClass, ph.r.Client); !priorityClassExist {
		ph.r.Recorder.Eventf(ph.scan, corev1.EventTypeWarning, "PriorityClass", why+" Scan:"+ph.scan.Name)
		pod.Spec.PriorityClassName = ""
	}
	return ph.r.launchScanPod(ph.scan, pod, ph.l)
}
///
/// changes to handle CEL pod creation in PlatformScanTypeHandler
func (r *ReconcileComplianceScan) newPlatformScanPod(scanInstance *ComplianceScan) *corev1.Pod {
    pod := createBasePod(...) // common volumes, environment

    if scanInstance.Spec.ScannerType == ScannerTypeCelScanner {
        // single container
        container := corev1.Container{
            Name:  "scanner",
            Image: CEL_SCANNER_IMAGE, // or operator image with subcommand
            Command: []string{
              "compliance-operator", 
              "cel-scanner", // subcommand that does fetch + evaluate
              // arguments
              "--profile=" + scanInstance.Spec.Profile,// this will be tailoredProfile name
            },
        }
        pod.Spec.Containers = append(pod.Spec.Containers, container)
    } else {
        // existing OpenSCAP containers
        // [openscap + log-collector...]
    }

    return pod
}
```


#### 3.2 The “cel-scanner” Logic

**Entrypoint** (pseudocode in `cmd/manager/cel_scanner.go`):

```go
func main() {
  // parse flags: --profile, etc.
  // 1. Identify which TailoredProfile or set of rules we need to evaluate
  // 2. For each rule (or each "CustomRule" reference):
  //    a) fetch the cluster resources per `inputs[]`
  //    b) evaluate the `expression`
  //    c) record pass/fail
  // 3. Write out final JSON or create ConfigMaps or direct CCR objects
  // 4. Exit with success code
}
```

**Implementation Steps:**

1. **Fetch `TailoredProfile`** CR Instance for the given `--profile`.  
2. **Gather Rule references** from `TailoredProfile.spec.enableRules`. For each `CustomRule`:  
   - Read `spec.inputs[]` to know which GVR (Group/Version/Resource) to fetch.  
3. **Gather Required Resources**
   - Make an in-cluster request (via the k8s API) to retrieve all objects that match, we will reuse the fetch function existing `api-resource-collector`.
   - Insert the retrieved JSON list into the CEL environment.  
3. **Evaluate** `spec.expression` with the CEL evaluator.  
   - If the expression yields `true`, the rule passes.  
   - Else, the rule fails, and we store `spec.errorMessage`.  
4. **Generate** either a direct `ComplianceCheckResult` object or build a JSON snippet save to `ConfigMap`, or forward it

**Evaluation Example**:

```go
// runPlatformScan runs the platform scan based on the profile and inputs.
func (c *CelScanner) runPlatformScan() {
	DBG("Running platform scan")
	// Load and parse the profile
	profile := c.celConfig.Profile
	if profile == "" {
		FATAL("Profile not provided")
	}
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}
	exitCode := 0
	// Check if a tailored profile is provided, and get selected rules
	var selectedRules []*cmpv1alpha1.CustomRUle
	if c.celConfig.Tailoring != "" {
		tailoredProfile, err := c.getTailoredProfile(namespace)
		if err != nil {
			FATAL("Failed to get tailored profile: %v", err)
		}
		selectedRules, err = c.getSelectedRules(tailoredProfile)
		if err != nil {
			FATAL("Failed to get selected rules: %v", err)
		}
	} else {
		FATAL("No tailored profile provided")
	}
	evalResultList := []*v1alpha1.RuleResult{}
	// Process each selected rule
	for _, rule := range selectedRules {
		DBG("Processing rule: %s\n", rule.Name)
		// Collect the necessary resources from the mounted directory based on rule inputs
		resultMap := c.collectResourcesFromKubeAPI(rule)
		DBG("Collected resources: %v\n", resultMap)
		// Create CEL declarations
		declsList := createCelDeclarations(resultMap)
		// Create a CEL environment
		env := createCelEnvironment(declsList)
		// Compile and evaluate the CEL expression
		ast, err := compileCelExpression(env, rule.Expression)
		if err != nil {
			FATAL("Failed to compile CEL expression: %v", err)
		}
		result := evaluateCelExpression(env, ast, resultMap, rule)
		if result.Status == v1alpha1.CheckResultFail {
			exitCode = 2
		} else if result.Status == v1alpha1.CheckResultError {
			exitCode = -1
		}
		evalResultList = append(evalResultList, &result)
	}
	// Save the scan result
  // We will decide what to do with result in the next step
	saveScanResult(evalResultList)
}
```

**Write results**:  
- Option 1 (Two-step, aggregator style): Summarize pass/fail into a `ConfigMap` with a small JSON array of results:
  ```json
  [
    {
      "id": "my_cel_rule_example",
      "status": "FAIL",
      "message": "Application Namespaces do not have a NetworkPolicy.",
      
    }
  ]
  ```
  The aggregator sees the `ConfigMap` (by label) and creates corresponding `ComplianceCheckResult` objects.  
- Option 2 (Direct creation of `ComplianceCheckResult` CRs from the scanner): The scanner can create them in-cluster immediately.  

Depending on the desired flow, we can either **continue the aggregator approach** or have the “cel-scanner” do it directly.  

### 4. Aggregation (Optional)

If the aggregator approach is kept:
1. It watches for `ConfigMaps` labeled with `compliance.openshift.io/result-type=celscan`.
2. It reads the JSON content from the `ConfigMap`.
3. For each item in the JSON array:
   - Looks up or cross-references the `CustomRule` (by ID).
   - Creates (or updates) a `ComplianceCheckResult` object with `status=PASS`/`FAIL`.

### 5. ScanSettingBinding Controller

When a user creates a `ScanSettingBinding` that references `TailoredProfile`:
1. The controller checks if the `TailoredProfile` has a `scannerType` annotation set to `"cel"`. 
2. If yes, it sets `ComplianceScan.Spec.ScannerType = "cel"`. 
3. Otherwise default to `openscap`.

**Pseudo-code snippet**:

```go
func (r *ReconcileScanSettingBinding) createComplianceScanForProfile(tp *TailoredProfile) *ComplianceScan {
  scan := &ComplianceScan{}
  // ...
  if tp.GetAnnotations()["compliance.openshift.io/scanner-type"] == "cel" {
    scan.Spec.ScannerType = compv1alpha1.ScannerTypeCelScanner
  } else {
    scan.Spec.ScannerType = compv1alpha1.ScannerTypeOpenSCAP
  }
  return scan
}
```

### 6. TailoredProfile Controller

- Ensures that if a `TailoredProfile` references a `CustomRule` (with `scannerType: cel`), the resulting annotation `scanner-type: cel` is set.  
- For **custom** TailoredProfiles (where you only have `CustomRule`s and no `ProfileBundle` or “extends” parent), the operator will skip the SCAP `tailoredProfile` Datastream `ConfigMap` generation. Instead, it sets `annotation[scanner-type]=cel`.

**Pseudo-code**:

```go
func (r *ReconcileTailoredProfile) Reconcile(request reconcile.Request) (reconcile.Result, error) {
  tp := &TailoredProfile{}
  err := r.client.Get(ctx, request.NamespacedName, tp)
  // ...
  foundCel := false
  for each ruleRef in tp.Spec.EnableRules {
     if isCustomRule(ruleRef) {
       foundCel = true
       break
     }
  }
  if foundCel {
     // ensure annotation is set
     ann := tp.GetAnnotations()
     ann["compliance.openshift.io/scanner-type"] = "cel"
     tp.SetAnnotations(ann)
     r.client.Update(ctx, tp)
  }
  // also make sure only one type of rule are there
  // ...
}
```

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


### The Implementation “Flow”

Putting it all together:

1. **User** defines a `CustomRule` with `scannerType:"cel"`.
2. **User** creates a `TailoredProfile` that enables that custom rule (optionally with other rules).
3. The **TailoredProfile Controller** sees it references `CustomRule` -> sets `compliance.openshift.io/scanner-type: cel` annotation on the `TailoredProfile`.
4. **User** creates a `ScanSettingBinding` referencing that `TailoredProfile`.
5. **ScanSettingBinding Controller** sees the `TailoredProfile` annotation -> creates a `ComplianceScan` with `spec.scannerType="cel"`.
6. **ComplianceScan Controller** sees `scannerType="cel"` -> creates a single Pod with `cel-scanner` container.
7. The **`cel-scanner` container**:
   - Fetch the `TailoredProfile`.
   - Loads references to `CustomRule`s from the `TailoredProfile`.
   - Fetches resources listed in `spec.inputs[]`.
   - Evaluates `spec.expression` in CEL.
   - Writes `ComplianceCheckResult` directly or write pass/fail results into a `ConfigMap` or (If aggregator is used) The `Aggregator` sees the results and creates or updates `ComplianceCheckResult` objects to reflect pass/fail.

### Example Pseudo-Code Blocks

Below are additional code fragments (from the diffs) illustrating the main changes in each component.

---

#### New Fields/Enums in `pkg/apis/compliance/v1alpha1/custom_rule_type.go`
```go
// ScannerTypeEnum is an enum for the scanner type
type ScannerTypeEnum string

const (
  ScannerTypeOpenSCAP   ScannerTypeEnum = "openscap"
  ScannerTypeCelScanner ScannerTypeEnum = "cel"
  ScannerTypeUnknown    ScannerTypeEnum = "unknown"
)

type RulePayload struct {
  ID          string           `json:"id"`
  // ...
  ScannerType ScannerTypeEnum  `json:"scannerType,omitempty"`
  Expression  string           `json:"expression,omitempty"`
  Inputs      []InputParameter `json:"inputs,omitempty"`
  ErrorMessage string          `json:"errorMessage,omitempty"`
}

type InputParameter struct {
  Name      string `json:"name"`
  Type      string `json:"type,omitempty"` // e.g. JSON array, typed struct, etc.
  APIGroup  string `json:"apiGroup"`
  Version   string `json:"version"`
  Resource  string `json:"resource"`
  Namespace string `json:"namespace,omitempty"` // This can be empty depends on resources
}
```

#### Adjusting `ComplianceScan` CRD to Add `scannerType`
```yaml
  spec:
    scannerType:
      type: string
      description: "The type of scanner to use for the scan. Defaults to openscap."
      default: "openscap"
```

#### Changes in `ScanSettingBinding` Controller
When building the `ComplianceScan` object from a `Profile`, we set `spec.scannerType` if the `TailoredProfile` annotation indicates `"cel"`:

```go
func setScanTypeAndScanner(scan *ComplianceScanSpecWrapper, annotations map[string]string) error {
   scanType, err := getScanType(annotations)
   if err != nil {
     return err
   }
   scan.ComplianceScanSpec.ScanType = scanType

   scannerType, err := getScannerType(annotations)
   if err != nil {
     // fallback or handle error
   }
   scan.ComplianceScanSpec.ScannerType = scannerType
   return nil
}
```

### Test Plan

1. **Unit Tests**  
   - Validate `CustomRule` fields (e.g., `inputs`, `expression`).
   - Test parsing and evaluating CEL expressions.

2. **End-to-End Tests**  
   - Deploy operator.  
   - Create one or more `CustomRule`s.  
   - Create `TailoredProfile` referencing these `CustomRule`s.  
   - Confirm the single “cel-scanner” Pod runs, collects resources, and produces `ComplianceCheckResult`s.  

3. **Load / Scale Tests**  
   - Evaluate performance with large sets of cluster resources or numerous `CustomRule`s.

### Upgrade / Downgrade Strategy

- This is a **TechPreview** feature. The `CustomRule` CRD may evolve over time.  
- Existing `ComplianceScan` functionality is **unchanged**; users can selectively adopt CEL scanning.

### Failure Modes


### Support Procedures
