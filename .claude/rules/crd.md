---
paths:
  - "pkg/apis/**"
---

# CRD Rules — Compliance Operator

Applies to `pkg/apis/compliance/v1alpha1/` — the CRD types backing every public CR in this operator.

## Adding a field

1. Edit `<crd>_types.go`. Place new fields under the existing `Spec` or `Status` struct.
2. New fields **must be optional** unless you're cutting a new API version. Use a pointer type or `omitempty` so existing CRs validate.
3. Add `+kubebuilder` markers for validation (`+kubebuilder:validation:Enum`, `+kubebuilder:default:=...`, etc.) — relying on controller-side validation alone makes for bad UX.
4. Run `make manifests generate`. This regenerates:
   - `zz_generated_deepcopy.go` (must be committed)
   - `bundle/manifests/*.yaml` (CRD manifests)
   - `config/crd/bases/*.yaml`
5. Include all generated files in the same commit as the type change.

## Renaming / removing a field

Don't, in `v1alpha1`. Either:
- Mark the field deprecated (godoc comment), keep it accepted, route logic to the new field.
- Or cut a new API version (`v1alpha2`) and provide a conversion webhook.

The Compliance Operator has an installed user base across OpenShift versions — a silent rename will break upgrades.

## Webhook validation

- CRDs with `CustomRule`, `TailoredProfile` have validating webhooks. Logic lives in the corresponding controller package's `webhook.go` (or in `pkg/utils/celvalidation/` for CustomRule).
- Validation that can be expressed declaratively (`+kubebuilder:validation:*`) should be. Webhook code is reserved for cross-field invariants.

## Status subresource

- The `+kubebuilder:subresource:status` marker on the type means `Status` is updated separately. Controllers must use `r.Status().Update()`.

## Discipline

- Don't expose internal-only fields on the spec. If a controller needs to remember something, put it on status, not spec.
- Don't add a field that exists only to make a single test pass — that's a test-shaped hole in the API.
- Don't change kubebuilder defaults silently; existing CRs may rely on the old default.
