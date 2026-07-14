# celctl reference — rule file format & commands

`celctl` replaces the cel-rpc-server MCP server. Rules live in the ComplianceAsCode/content
repo — see the `celctl cac` section; `verify`/`eval` accept ad-hoc rule/test files.

## Rule file format

```json
{
  "id": "all-namespaces-network-policy",
  "name": "All Namespaces Network Policy Requirement",
  "description": "Every namespace must have at least one NetworkPolicy.",
  "expression": "namespaces.items.all(ns, networkpolicies.items.exists(np, np.metadata.namespace == ns.metadata.name))",
  "inputs": [
    {"name": "namespaces",      "kubernetes": {"version": "v1", "resource": "namespaces"}},
    {"name": "networkpolicies", "kubernetes": {"group": "networking.k8s.io", "version": "v1", "resource": "networkpolicies"}}
  ],
  "category": "security",
  "severity": "high",
  "tags": ["network-security", "network-policy"],
  "test_cases": [
    {"description": "ns with matching netpol passes", "expected_result": true,
     "test_data": {
       "namespaces":      {"items": [{"metadata": {"name": "app"}}]},
       "networkpolicies": {"items": [{"metadata": {"name": "deny", "namespace": "app"}}]}
     }},
    {"description": "ns without netpol fails", "expected_result": false,
     "test_data": {
       "namespaces":      {"items": [{"metadata": {"name": "app"}}]},
       "networkpolicies": {"items": []}
     }},
    {"description": "no namespaces — vacuously true", "expected_result": true,
     "test_data": {"namespaces": {"items": []}}}
  ],
  "metadata": {
    "compliance_framework": "CIS",
    "control_ids": ["5.3.2"],
    "references": ["https://www.cisecurity.org/benchmark/kubernetes"]
  }
}
```

Notes:
- `test_data` values may be an **inline JSON object** (above) *or* a **JSON string**
  (cel-rpc-server's on-disk format, e.g. `"{\"items\":[...]}"`). celctl accepts both.
- An input not present in a test case's `test_data` defaults to an empty List `{"items":[]}`.

## verify — evaluate against test cases (no cluster)

```bash
# whole rule file:
celctl verify --rule myrule.json

# ad-hoc expression + a JSON array of test cases:
celctl verify --expr 'pods.items.all(p, p.metadata.name != "")' --test cases.json
```

`cases.json` is just the `test_cases` array:

```json
[
  {"description": "named ok", "expected_result": true,
   "test_data": {"pods": {"items": [{"metadata": {"name": "x"}}]}}},
  {"description": "empty name fails", "expected_result": false,
   "test_data": {"pods": {"items": [{"metadata": {"name": ""}}]}}}
]
```

Output: per-case PASS/FAIL and `N/M passed`. Exit code 0 only if all pass.

## eval — evaluate once, print the boolean

```bash
echo '{"items":[{"spec":{"hostNetwork":true}}]}' > pods.json
celctl eval --expr 'pods.items.filter(p, p.spec.hostNetwork == true).size() == 0' --data pods=pods.json
# prints: false   (exit 1)
```

`--data name=path.json` is repeatable; each file is the List for that variable.

## live — evaluate against the cluster (needs kubectl)

```bash
# from a rule file (uses its inputs' group/version/resource/namespace):
celctl live --rule myrule.json

# ad-hoc:
celctl live --expr 'deployments.items.all(d, d.spec.replicas >= 2)' \
            --input deployments=apps/v1/deployments:production
```

Input spec: `name=[group/]version/resource[:namespace]`
- core type, all namespaces: `pods=v1/pods`
- core type, one namespace:  `pods=v1/pods:default`
- grouped type:              `deployments=apps/v1/deployments:production`

celctl runs `kubectl get <resource>.<version>.<group> -o json` (with `-n ns` or `-A`),
binds the result, evaluates, and prints fetched counts + PASS / FAIL.

## discovery

```bash
celctl discover                              # kubectl api-resources --verbs=list -o wide
celctl samples configmaps -n openshift-etcd --max 3   # real objects to model test data on
```

## cac-content rules (`celctl cac …`)

For rules in the ComplianceAsCode/content repo
(`applications/<app>/<rule>/cel/shared.yml`). celctl binds inputs **exactly like the
Compliance Operator scanner**:

- input **with** `resource_name` → single object (`hco.spec...`)
- input **without** `resource_name` → List wrapper `{items:[...]}` (`hcoList.items.all(...)`)

```bash
# lint: compile + smoke-eval, catches "iterating a list input without .items"
celctl cac lint applications/openshift-virtualization/kubevirt-nonroot-feature-gate-is-enabled

# unit-test against fixtures
celctl cac test <rule-dir> --cases cases.yaml

# one-shot with a single mock input
celctl cac test <rule-dir> --mock hcoList=hco.yaml --expect true

# evaluate against the live cluster (kubectl)
celctl cac live <rule-dir>
```

Fixtures file (`cases.yaml`) — each input value is raw resource data; for a list input
provide `{items:[...]}` (or a bare array), for a `resource_name` input provide the object:

```yaml
- name: nonRoot enabled -> compliant
  expect: true
  inputs:
    hcoList:
      items:
        - metadata: {name: kubevirt-hyperconverged, namespace: openshift-cnv}
          spec: {featureGates: {nonRoot: true}}
- name: nonRoot false -> non-compliant
  expect: false
  inputs:
    hcoList:
      items:
        - metadata: {name: kubevirt-hyperconverged, namespace: openshift-cnv}
          spec: {featureGates: {nonRoot: false}}
- name: no HCO present -> non-compliant (size != 1)
  expect: false
  inputs:
    hcoList: {items: []}
```

celctl auto-discovers `<rule-dir>/cel/tests/*.yaml` (same format) when `--cases`/`--mock`
are omitted, so fixtures can live alongside the rule.

## scaffolding fixtures (`celctl cac scaffold`)

Never hand-invent resource shapes — schemas change across versions (HyperConverged
`featureGates` is an object on v1beta1 but an array on v1; `nonRoot` was removed in
4.18+). Seed fixtures from real objects:

```bash
# with a cluster: fetch each input via the rule's own kubernetes_input_spec,
# sanitize (managedFields/uid/resourceVersion/... stripped), stamp provenance
celctl cac scaffold <rule-dir> --from-cluster

# without a cluster: binding-shaped skeleton, provenance marked as such
celctl cac scaffold <rule-dir>
```

Output is the wrapper fixture format (bare-list files remain valid):

```yaml
provenance:
  fetched_with: celctl cac scaffold --from-cluster
  date: "2026-07-14"
  openshift_version: 4.21.0          # versions only — never cluster-identifiable info
  kubernetes_version: v1.35.3
  source_api_versions:
    hcoList: hco.kubevirt.io/v1beta1  # the shape the cluster actually served
cases:
  - name: ...
    expect: true
    inputs: { ... }
```

Fill the TODO cases (mutate only the interesting field), then `celctl cac test <rule-dir>`.
Review fixtures for cluster-identifiable values before committing — versions are OK.
