---
title: cel-scanner-rule-crd
authors:
  - Vincent056
reviewers:
  - TBD
approvers:
  - TBD
api-approvers:
  - TBD
creation-date: 2026-03-06
last-updated: 2026-03-06
tracking-link:
  - TBD
see-also:
  - "/enhancements/this-other-neat-thing.md"
replaces:
  - "/enhancements/that-less-than-great-idea.md"
superseded-by:
  - "/enhancements/our-past-effort.md"
---

# CEL Scanner Support for the Rule CRD

## Summary

Extend the existing `Rule` CRD with optional CEL fields so the profile parser
can produce CEL-based rules and profiles from content bundles. This enables
shipping CEL rules as part of compliance content and adds a CEL content
pipeline through `ProfileBundle`. The parser validates CEL expressions at
creation time and sets scanner-type annotations directly on Profiles.

## Motivation

We want to **ship** CEL-based compliance rules as part of compliance content,
the same way we ship OpenSCAP/XCCDF rules today. The parser creates `Rule` CRs
from content bundles; it does not create `CustomRule` CRs. `CustomRule` is
designed for and should remain exclusively **user-created** -- it is the
mechanism for users to define their own ad-hoc CEL checks via
`TailoredProfile`.

Since the parser produces `Rule` CRs (not `CustomRule` CRs), the `Rule` CRD
must support CEL fields to enable shipping CEL rules. Today the `Rule` CRD
only supports OpenSCAP/XCCDF rules, so there is no way to ship CEL-based
compliance content through the standard content pipeline (`ProfileBundle` ->
parser -> `Rule` + `Profile` CRs).

Additionally, the current CEL scanning path only works through
`TailoredProfile` with a hardcoded `--tailoring=true` flag. There is no way
to have a `Profile` that directly contains CEL rules, and
`ScanSettingBinding` always requires `ProfileBundle` content data, even though
CEL scans do not need it.

### Goals

1. Extend the `Rule` CRD to support CEL fields (`scannerType`, `expression`,
   `inputs`, `failureReason`) so the parser can create CEL rules as regular
   `Rule` CRs.
2. Eliminate the `CustomRulePayload` struct duplication by moving CEL fields
   into the shared `RulePayload`.
3. Support `Profile` CRs that contain only CEL-type `Rule` CRs, created by
   the parser.
4. Have the parser validate CEL expressions at creation time and set the
   `scanner-type` annotation directly on Profiles. Validation errors surface
   via `ProfileBundle` status.
5. Set explicit `scannerType` on every `Rule` (both OpenSCAP and CEL); no
   more implicit empty-means-OpenSCAP.
7. Support a CEL content pipeline: individual YAML source files bundled into
   a single validated file via the `pkg/celcontent` bundler utility, declared
   via a new optional `celContentFile` field on `ProfileBundleSpec`.
8. Enable the CEL scanner to load rules from `Profile` CRs (not just
   `TailoredProfile`), adding a `--tailoring=false` path.

### Non-Goals

1. Implementing mutation protection (validating webhook) for parser-created
   `Rule` and `Profile` CRs. This may be addressed in a follow-up enhancement.

## Proposal

### Key Assumptions

- A profile contains only one type of rule (all CEL or all OpenSCAP, never
  mixed).
- The parser creates `Rule` and `Profile` CRs. Users only create
  `TailoredProfile` and `CustomRule` CRs.
- `CustomRule` remains available for user-created CEL rules.

### User Stories

1. As a content author, I want to write CEL-based compliance rules in
   individual YAML files that are bundled and shipped inside a content image
   alongside XCCDF DataStream content.
2. As a cluster administrator, I want the Compliance Operator to
   automatically parse CEL content from a `ProfileBundle` and create `Rule`
   and `Profile` CRs, so I can scan using CEL profiles without manually
   creating `CustomRule` resources.
3. As a cluster administrator, I want to create a `ScanSettingBinding` that
   references a CEL `Profile` directly, without needing a `TailoredProfile`.
4. As a cluster administrator, I want to use `TailoredProfile` to extend or
   customize a CEL `Profile` by enabling or disabling individual CEL `Rule`
   CRs, just like I do with OpenSCAP profiles.
5. As a cluster administrator, I want every `Profile` and `Rule` to have an
   explicit scanner type so I can easily determine which scanner evaluates
   each resource.

### API Extensions

#### Rule CRD

Add optional CEL fields to `RulePayload`:

```go
type RulePayload struct {
    // ... existing fields (ID, Title, Description, etc.) ...

    // +optional
    // +kubebuilder:validation:Enum=OpenSCAP;CEL
    ScannerType ScannerType `json:"scannerType,omitempty"`
    // +optional
    Expression string `json:"expression,omitempty"`
    // +optional
    Inputs []InputPayload `json:"inputs,omitempty"`
    // +optional
    FailureReason string `json:"failureReason,omitempty"`
}
```

No `RuleStatus` subresource is needed. Parser-created Rules are immutable
(owned by `ProfileBundle`). The parser validates CEL expressions at creation
time and reports errors via `ProfileBundle` status.

The `Rule` struct implements `scanner.Rule` and `scanner.CelRule` interfaces
from the compliance SDK, with shared helper methods on `RulePayload`
(`ToScannerInputs()`, `ToScannerMetadata()`) to avoid duplication with
`CustomRule`.

#### CustomRule CRD (Deduplication)

Since the four CEL fields (`scannerType`, `expression`, `inputs`,
`failureReason`) now live in `RulePayload`, the `CustomRulePayload` struct
becomes redundant. `CustomRuleSpec` is simplified to embed only `RulePayload`:

```go
type CustomRuleSpec struct {
    RulePayload `json:",inline"` // CustomRulePayload removed
}
```

This is CRD-compatible because both `RulePayload` and `CustomRulePayload`
were `json:",inline"`, so JSON paths like `spec.scannerType` remain identical.
The `CustomRule.Validate()` method continues to enforce that CEL fields are
required at runtime.

#### Profile CRD

No changes to the `Profile` struct. No `ProfileStatus` subresource is needed.
Parser-created Profiles are immutable (owned by `ProfileBundle`). The parser
sets the `scanner-type` annotation directly at creation time.

#### ProfileBundle CRD

Add an optional `celContentFile` field:

```go
type ProfileBundleSpec struct {
    ContentImage   string `json:"contentImage"`
    ContentFile    string `json:"contentFile"`
    // +optional
    CELContentFile string `json:"celContentFile,omitempty"`
}
```

### Implementation Details/Notes/Constraints

#### Parser Validation (No Rule or Profile Controllers)

No new controllers are needed for `Rule` or `Profile`. Parser-created
resources are immutable (owned by `ProfileBundle`), so there is nothing to
re-validate after creation. Instead, the **profileparser** handles everything
at creation time:

- Calls `celvalidation.ValidateCELRule()` when creating CEL Rule CRs. This
  shared function (in `pkg/utils/celvalidation/`) is also used by the
  `CustomRule` controller for user-created rules.
- Sets `scanner-type` annotation on Profile CRs (`OpenSCAP` or `CEL`).
- Sets `product-type=Platform` annotation on CEL Profiles.
- Sets `scannerType: OpenSCAP` on all XCCDF Rule CRs.
- Sets `compliance.openshift.io/rule-variable` on CEL Rules that declare
  `variables`, listing the `Variable` CRs the rule depends on.
- Sets `control.compliance.openshift.io/<standard>` and RHACM annotations
  on CEL Rules that declare `controls`, consistent with XCCDF reference
  parsing.
- Populates `Profile.Values` for CEL Profiles from the `values` field in
  the CEL content YAML, so the scanner can load default variable values.
- Reports validation errors via `ProfileBundle` status (the existing error
  reporting mechanism).

The `CustomRule` controller continues to handle user-created CEL rules, which
can change at any time and require re-validation.

#### TailoredProfile Controller

Updated to detect CEL scanner type from `Rule.scannerType` field when
`kind: Rule` is used in `enableRules`, in addition to the existing
`kind: CustomRule` detection. Enforces the single-type-per-profile assumption.

#### ScanSettingBinding Controller

Updated to handle CEL Profiles:

- Skips `fillContentData()` (ProfileBundle content lookup) when the Profile
  or TailoredProfile has `scanner-type=CEL` annotation.
- Passes `--tailoring=false` for direct CEL Profile scans, `--tailoring=true`
  for TailoredProfile CEL scans.

#### CEL Scanner

Updated `cmd/manager/cel-scanner.go`:

- New Profile path (`--tailoring=false`): loads `Rule` CRs from the `Profile`
  referenced in the `ComplianceScan`.
- Existing TailoredProfile path (`--tailoring=true`): updated to load `Rule`
  CRs (with `scannerType=CEL`) in addition to `CustomRule` CRs.
- Result mapping generalized to use the `scanner.Rule` interface.

#### ComplianceScan Pod

Updated `pkg/controller/compliancescan/scan.go`: the `--tailoring` flag is
set dynamically based on whether the scan originated from a Profile (false) or
TailoredProfile (true), instead of being hardcoded to true.

#### CEL Content Pipeline

**Source structure** (in CaC/content or compliance-operator repo):

```
cel-rules/
  check-default-namespace-has-no-pods.yaml
  check-namespaces-have-resource-quotas.yaml
  check-cluster-admin-bindings.yaml
cel-profiles/
  cel-e2e-test-profile.yaml
```

Each rule file is a standalone YAML containing the full rule definition
(name, id, title, severity, expression, inputs, controls, etc.). Each
profile file is a standalone YAML listing the profile metadata and rule
references.

Example individual rule file (`cel-rules/check-default-namespace-has-no-pods.yaml`):

```yaml
name: check-default-namespace-has-no-pods
id: check_default_namespace_has_no_pods
title: Default namespace must not contain application pods
severity: medium
checkType: Platform
expression: |
  pods.items.filter(p,
      p.metadata.namespace == 'default' &&
      !p.metadata.name.startsWith('kubernetes')
  ).size() == 0
inputs:
  - name: pods
    kubernetesInputSpec:
      apiVersion: v1
      resource: pods
      resourceNamespace: default
failureReason: Application pods are running in the default namespace.
controls:
  NIST-800-53:
    - "AC-6"
    - "CM-7"
  CIS-OCP:
    - "5.7.4"
```

Example individual profile file (`cel-profiles/cel-e2e-test-profile.yaml`):

```yaml
name: cel-e2e-test-profile
id: cel_e2e_test_profile
title: CEL E2E Test Profile
productType: Platform
rules:
  - check-default-namespace-has-no-pods
  - check-namespaces-have-resource-quotas
  - check-cluster-admin-bindings
```

**Bundler utility** (`pkg/celcontent`): A Go package that reads individual
rule and profile YAML files from their respective directories and assembles
them into a single validated bundle YAML file.

```go
import "github.com/ComplianceAsCode/compliance-operator/pkg/celcontent"

// Generate a bundle from directories
bundle, err := celcontent.BundleFromDirs("cel-rules/", "cel-profiles/")

// Or write directly to a file
err := celcontent.BundleToFile("cel-rules/", "cel-profiles/", "cel-content.yaml")
```

The bundler performs the following validations:
- Each rule must have a `name`, `expression`, and at least one `input`.
- Each profile must have a `name` and at least one `rule`.
- Duplicate rule names across files are rejected.
- Profile rule references are validated against the loaded rule set.
- Non-YAML files (README.md, .gitkeep, etc.) are silently ignored.
- Rules and profiles are sorted alphabetically by name for deterministic output.

**Build step**: The bundler assembles individual YAMLs into a single
bundled file at build time. The bundle format:

```yaml
rules:
  - name: pods-must-have-security-context
    id: check_pods_must_have_security_context
    title: Pods must have security context
    severity: medium
    checkType: Platform
    expression: "pods.items.all(p, has(p.spec.securityContext))"
    inputs:
      - name: pods
        kubernetesInputSpec:
          apiVersion: v1
          resource: pods
    failureReason: "Some pods do not have a security context"
    variables:               # optional: Variable CRs this rule depends on
      - var-pod-timeout
    controls:                # optional: compliance standard references
      NIST-800-53:
        - "CM-6(a)"
      CIS-OCP:
        - "5.2.1"
profiles:
  - name: cel-security-profile
    id: cel_profile_security
    title: CEL Security Profile
    productType: Platform
    rules:
      - pods-must-have-security-context
    values:                  # optional: Variable CRs referenced by the profile
      - var-pod-timeout
```

**Delivery**: The content image ships both files:

```
/ssg-ocp4-ds.xml       # XCCDF DataStream (existing)
/cel-content.yaml      # CEL bundle (new, optional)
```

**ProfileBundle** declares both via spec fields:

```yaml
apiVersion: compliance.openshift.io/v1alpha1
kind: ProfileBundle
metadata:
  name: ocp4
spec:
  contentImage: ghcr.io/complianceascode/k8scontent:latest
  contentFile: ssg-ocp4-ds.xml
  celContentFile: cel-content.yaml
```

**Parser changes**:

- New `--cel-path` CLI flag. ProfileBundle controller passes it only when
  `celContentFile` is set.
- `runProfileParser()` handles both `--ds-path` (XCCDF) and `--cel-path`
  (CEL). At least one must be provided.
- New `ParseCELBundle()` function reads the YAML bundle, creates `Rule` CRs
  with `scannerType=CEL` and `Profile` CRs with `scanner-type=CEL` annotation.
- CEL Rule annotations set by the parser:
  - `compliance.openshift.io/rule` — rule identifier
  - `compliance.openshift.io/profiles` — which profiles include the rule
  - `compliance.openshift.io/rule-variable` — which `Variable` CRs the rule
    depends on (from `variables` in the YAML)
  - `control.compliance.openshift.io/<standard>` — compliance controls (from
    `controls` in the YAML, e.g. `NIST-800-53`, `CIS-OCP`)
  - `policies.open-cluster-management.io/standards` and `/controls` — RHACM
    standard/control annotations (derived from `controls`)
- CEL Profile values: `Profile.Values` populated from the optional `values`
  list in the YAML, allowing the CEL scanner to load `Variable` CRs.
- Existing XCCDF path updated to set `scannerType: OpenSCAP` on all Rules.

**Variables**: CEL rules reuse `Variable` CRs created by the XCCDF DataStream
parser from the same `ProfileBundle`. The CEL content YAML does not define its
own variables. This works because a `ProfileBundle` ships both XCCDF and CEL
content from the same image, and the XCCDF DataStream already defines all the
variables that CEL rules may reference. Users override variable values via
`TailoredProfile.spec.setValues`, which works identically for both OpenSCAP
and CEL scans.

A future iteration may add a `variables` section to the CEL content format for
bundles that ship CEL-only content without an accompanying XCCDF DataStream.

#### Backward Compatibility

- `CustomRule` CRD is NOT removed. Existing TailoredProfiles referencing
  `kind: CustomRule` continue to work unchanged.
- `CustomRulePayload` type is removed; `CustomRuleSpec` embeds only
  `RulePayload`. JSON API surface is unchanged since both were inline.
- OpenSCAP Rules get explicit `scannerType: OpenSCAP` (previously empty).
- Parser sets `scanner-type` annotation on all Profiles at creation time.
- No new status subresources on Rule or Profile (parser-created, immutable).

### Risks and Mitigations

**Risk**: Removing `CustomRulePayload` and changing `CustomRuleSpec` could
break the generated CRD if field validation markers differ.

**Mitigation**: CEL fields on `RulePayload` are `+optional`. The
`CustomRule.Validate()` runtime method enforces required fields for
CustomRules. The JSON wire format is identical.

**Risk**: Setting `scannerType: OpenSCAP` on all existing Rules changes the
stored representation.

**Mitigation**: The parser already overwrites Rule CRs on every reconcile via
`createOrUpdate`. The field is additive and does not change behavior for
existing OpenSCAP rules.

## Design Details

### Open Questions

1. Should we eventually deprecate `CustomRule` in favor of `Rule` with
   `scannerType=CEL`? The current design keeps both for backward compatibility
   but `Rule` is now a strict superset.

### Test Plan

- **Unit tests**: Shared CEL validation (compile success/failure), scanner
  interface parity between Rule and CustomRule, TailoredProfile with CEL
  Rules, CEL scanner loading from Profile, parser CEL content parsing.
- **Bundler tests** (`pkg/celcontent/bundler_test.go`): Validates the bundler
  utility reads individual files from `tests/data/cel-rules/` and
  `tests/data/cel-profiles/`, produces correct bundle output, enforces
  duplicate detection, missing field validation, unknown rule references,
  and non-YAML file filtering. A roundtrip test verifies serialize/deserialize
  fidelity.
- **Parser integration tests** (`pkg/profileparser/cel_content_test.go`):
  Uses the bundler to generate a bundle from the individual test files at
  test time, then passes it through `ParseCELBundle` to verify correct
  `Rule` and `Profile` CR creation with all annotations, labels, and fields.
  A consistency test (`TestCELBundleCommittedFileMatchesBundler`) verifies
  the committed `tests/data/cel-content-test.yaml` stays in sync with the
  individual source files.
- **Test data organization**:
  - `tests/data/cel-rules/` — Individual CEL rule YAML files
  - `tests/data/cel-profiles/` — Individual CEL profile YAML files
  - `tests/data/cel-content-test.yaml` — Bundled output (regenerated from
    the individual files)
- **E2E test infrastructure**:
  - `images/testcontent/cel_content/` — Test content image directory
    containing `cel-content.yaml` bundle and `ssg-rhcos4-ds.xml` XCCDF XML.
  - `cel_content` tag in `images/testcontent/broken-content.sh` builds a
    test content image used by e2e tests.
  - `cmd/cel-bundler/` — CLI tool for regenerating the bundled YAML from
    individual rule/profile files.
  - `make cel-bundle` — Makefile target that regenerates
    `tests/data/cel-content-test.yaml` and copies it to the test image dir.
- **E2E tests** (`tests/e2e/parallel/main_test.go`):
  - `TestCELProfileBundle`: Creates a ProfileBundle with both XCCDF and CEL
    content. Verifies the ProfileBundle reaches VALID state, CEL Rules are
    created with correct `scannerType`, `expression`, `inputs`, annotations
    (`RuleIDAnnotationKey`, `RuleProfileAnnotationKey`), labels
    (`ProfileBundleOwnerLabel`), and severity. Verifies the CEL Profile has
    correct `scanner-type` annotation, `ProductTypeAnnotation`, all expected
    rule references, and `ProfileBundleOwnerLabel`.
  - `TestCELProfileScan`: Creates a ProfileBundle with CEL content, then a
    ScanSettingBinding referencing the CEL Profile. Waits for the scan to
    complete and verifies that ComplianceCheckResults are created for all
    three CEL rules.

### Upgrade / Downgrade Strategy

On upgrade to a version with this enhancement:

- Existing `Rule` CRs are unchanged. The new `scannerType` field is optional
  and defaults to empty. On the next ProfileBundle reconcile, the parser will
  set `scannerType: OpenSCAP` on all XCCDF rules.
- Existing `Profile` CRs are unchanged. On the next ProfileBundle reconcile,
  the parser will set the `scanner-type` annotation.
- Existing `CustomRule` CRs continue to work. The `CustomRuleSpec` struct
  change is wire-compatible.
- No user action is required for existing workloads.

Downgrade is not officially supported by the Compliance Operator. If
downgraded, the new `scannerType` field on Rules will be ignored by the older
operator version (unknown fields are preserved by Kubernetes).

### Version Skew Strategy

Not applicable. The Compliance Operator is a single installation within a
single cluster. All components (operator, parser, scanner) are deployed from
the same release.

### Operational Aspects of API Extensions

- No new controllers for Rule or Profile. CEL validation happens at parse
  time, adding negligible overhead to ProfileBundle reconciliation.
- The new `celContentFile` field on ProfileBundle is optional. Existing
  ProfileBundles without CEL content are unaffected.
- Expected usage: hundreds of Rules and tens of Profiles per cluster. No
  impact on general API throughput.

#### Failure Modes

- If the parser fails to validate a CEL expression, the ProfileBundle status
  is set to `INVALID` with an error message. The invalid Rule CR is not
  created. This is a fail-fast behavior.
- If the parser fails to read the CEL content file, the ProfileBundle status
  is set to `INVALID` with an error message. XCCDF content processing is
  independent and unaffected.

#### Support Procedures

- Check Rule scanner type: `oc get rules -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.scannerType}{"\n"}{end}'`
- Check Profile scanner-type annotation: `oc get profiles -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.annotations.compliance\.openshift\.io/scanner-type}{"\n"}{end}'`
- Check ProfileBundle status for CEL content errors: `oc get profilebundles -o yaml`
- Parser logs will show CEL compilation errors during content ingestion.

## Drawbacks

Adding CEL fields to `RulePayload` means OpenSCAP rules carry unused optional
fields in their schema. This is a minor schema bloat but avoids the larger
cost of maintaining two parallel CRDs.

## Alternatives

**Keep `CustomRule` as the only CEL CRD**: This is the current state. It
prevents the parser from producing CEL content and requires users to manually
create CustomRule resources for every CEL check. It also means CEL scanning
is only available through TailoredProfile.

**Convention-based CEL content discovery**: Instead of the explicit
`celContentFile` field, have the parser auto-discover CEL YAML files by
convention (e.g., `*.cel.yaml` in `/content/`). This is simpler but less
explicit and harder to debug when content is missing.

## Infrastructure Needed

CI resources for the Compliance Operator testing, similar to what we rely on
today. No new infrastructure is required.
