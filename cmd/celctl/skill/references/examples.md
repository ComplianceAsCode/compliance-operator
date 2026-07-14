# celctl reference — cac-content rule & fixture formats, every command

Rules live in the **ComplianceAsCode/content** repo as
`applications/<app>/<rule>/cel/shared.yml`, with unit-test fixtures in
`<rule-dir>/cel/tests/`. celctl binds inputs **exactly like the Compliance Operator
scanner** (it runs the operator's scanner engine):

- input **with** `resource_name` → single object (`hco.spec...`)
- input **without** `resource_name` → List wrapper `{items:[...]}` (`hcoList.items.all(...)`)

## Rule format (`<rule-dir>/cel/shared.yml`)

```yaml
check_type: Platform

failure_reason: |-
  The '.spec.featureGates.nonRoot' field is missing or not set to 'true' in
  the 'kubevirt-hyperconverged' resource.

inputs:
  - name: hcoList
    kubernetes_input_spec:
      api_version: hco.kubevirt.io/v1beta1   # group/version (just version for core)
      resource: hyperconvergeds              # plural resource
      # resource_namespace: openshift-cnv    # optional
      # resource_name: kubevirt-hyperconverged  # optional -> binds the single object

expression: |
  hcoList.items.all(h, ...)
```

The rule's human metadata (title, description, rationale, ocil) lives in the sibling
`rule.yml` as usual.

## Fixture format (`<rule-dir>/cel/tests/*.yaml`)

Generate with `celctl cac scaffold <rule-dir> --from-cluster`, then fill the TODO cases.

```yaml
provenance:
  fetched_with: celctl cac scaffold --from-cluster
  date: "2026-07-14"
  openshift_version: 4.22.0          # versions only — never cluster-identifiable info
  kubernetes_version: v1.35.5
  source_api_versions:
    hcoList: hco.kubevirt.io/v1beta1  # the shape the cluster actually served
cases:
  - name: nonRoot enabled -> compliant
    expect: true
    inputs:
      hcoList:
        items:
          - metadata: {name: kubevirt-hyperconverged, namespace: openshift-cnv}
            spec: {featureGates: {nonRoot: true}}
  - name: nonRoot disabled -> non-compliant
    expect: false
    inputs:
      hcoList:
        items:
          - metadata: {name: kubevirt-hyperconverged, namespace: openshift-cnv}
            spec: {featureGates: {nonRoot: false}}
  - name: no HyperConverged present -> non-compliant
    expect: false
    inputs:
      hcoList: {items: []}
```

Notes:
- Each input value is raw resource data: a `{items:[...]}` List (or bare array) for
  list inputs, the object itself for `resource_name` inputs — celctl normalizes either.
- A bare list of cases (no `provenance`/`cases` wrapper) is also accepted, but content
  CI requires the provenance block.
- Cover compliant, non-compliant, and the empty/absent edge (`all()` over `[]` is
  vacuously true).

## cac commands

```bash
# lint: compile + smoke-eval; catches "iterating a list input without .items"
celctl cac lint <rule-dir>

# scaffold fixtures; --from-cluster seeds them from real API objects
# (sanitized of managedFields/uid/resourceVersion/status, provenance-stamped)
celctl cac scaffold <rule-dir> --from-cluster
celctl cac scaffold <rule-dir>              # offline skeleton

# unit-test: auto-discovers cel/tests/*.yaml
celctl cac test <rule-dir>
celctl cac test <rule-dir> --cases other-cases.yaml
celctl cac test <rule-dir> --mock hcoList=hco.yaml --expect true   # one-shot

# evaluate against the live cluster via the operator's Kubernetes fetcher
celctl cac live <rule-dir>
```

Output uses PASS/FAIL/WARNING markers and `N/M cases passed`; exit code 0 only when
everything matches. A `no such key` eval error counts as FAIL (with a warning), exactly
as the operator scanner reports it.

## Skill install / update

```bash
celctl skill install        # writes this skill to ~/.claude/skills/cel-rule
celctl skill status         # installed vs binary version
```

## Ad-hoc expression helpers

For quick experiments outside a rule dir. Once the expression is right, move it into a
rule dir and use the cac commands.

```bash
# evaluate once, print true/false (exit 1 on false):
echo '{"items":[{"spec":{"hostNetwork":true}}]}' > pods.json
celctl eval --expr 'pods.items.filter(p, p.spec.hostNetwork == true).size() == 0' --data pods=pods.json

# run an expected-result matrix from a JSON file:
celctl verify --expr 'pods.items.all(p, p.metadata.name != "")' --test cases.json
```

`cases.json` is an array of `{description, expected_result, test_data}`:

```json
[
  {"description": "named ok", "expected_result": true,
   "test_data": {"pods": {"items": [{"metadata": {"name": "x"}}]}}},
  {"description": "empty name fails", "expected_result": false,
   "test_data": {"pods": {"items": [{"metadata": {"name": ""}}]}}}
]
```

`test_data` values may be inline JSON objects or JSON-encoded strings.

```bash
# ad-hoc live check (input spec: name=[group/]version/resource[:namespace]):
celctl live --expr 'deployments.items.all(d, d.spec.replicas >= 2)' \
            --input deployments=apps/v1/deployments:production
```

## Discovery helpers

```bash
celctl discover                                       # kubectl api-resources
celctl samples configmaps -n openshift-etcd --max 3   # real objects to model fixtures on
```
