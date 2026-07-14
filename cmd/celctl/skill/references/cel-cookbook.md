# CEL Cookbook (for Kubernetes compliance rules)

Patterns below are verified against the cel-go evaluation engine that `celctl` uses (the
same one the old cel-rpc-server used). Still, always round-trip your final expression
through `celctl verify` — treat this as a starting point, not a guarantee.

## The #1 rule: data is List-wrapped

Every input variable is bound to a Kubernetes **List**, i.e. an object with an `items`
array — *not* the bare resource. So you almost always start with `.items` and a macro:

```cel
pods.items.all(p, <condition>)      // every pod must satisfy condition
pods.items.exists(p, <condition>)   // at least one pod satisfies it
pods.items.filter(p, <cond>).size() == 0   // count of matches
```

This holds for both `verify_cel_with_tests` (your `inputs` test data is `{"items":[...]}`)
and `verify_cel_live_resources` (the server fetches each resource as a List).

## Empty-list semantics (test these explicitly)

| Expression over `items: []` | Result |
|---|---|
| `x.items.all(i, ...)` | `true`  (vacuously) |
| `x.items.exists(i, ...)` | `false` |
| `x.items.size() == 0` | `true` |

If "no resources present" should be a *pass*, `all()` already does that. If it should be a
*fail*, add `&& x.items.size() > 0` or use `exists`.

## Guard optional fields with has()

Dereferencing a missing key errors out. Guard first:

```cel
pods.items.all(p, has(p.spec.securityContext) && p.spec.securityContext.runAsNonRoot == true)

// map keys:
cm.items.all(c, has(c.data) && c.data["enabled"] == "true")
```

`has()` works on message fields and map keys. For lists, check `.size()` instead.

## Common building blocks

```cel
// String matching on a field
configs.items.exists(c, c.data["pod.yaml"].contains("--cert-file="))
nodes.items.all(n, n.metadata.name.startsWith("worker-"))
pods.items.all(p, p.metadata.name.matches("^app-[0-9]+$"))   // RE2 regex

// Numeric thresholds
deploys.items.all(d, d.spec.replicas >= 2)

// Nested list iteration (containers within pods)
pods.items.all(p, p.spec.containers.all(c, has(c.resources) && has(c.resources.limits)))

// Negation / "none should match"
pods.items.all(p, p.spec.hostNetwork != true)
pods.items.filter(p, p.spec.hostNetwork == true).size() == 0   // equivalent

// Default for possibly-missing scalar
pods.items.all(p, (has(p.spec.hostPID) ? p.spec.hostPID : false) == false)
```

## Correlating two resources (multi-input)

Bind two inputs and reference both. Classic "every namespace has a NetworkPolicy":

```cel
namespaces.items.all(ns,
  networkpolicies.items.exists(np, np.metadata.namespace == ns.metadata.name))
```

Both `namespaces` and `networkpolicies` must be declared as separate inputs.

## Gotchas

- **Bare object won't iterate.** Test data must be `{"items":[ {...} ]}`, not `{...}`.
- **`all()` on `[]` is `true`** — easy to write a rule that "passes" only because the
  cluster/test has zero resources. Always include an empty-list test case.
- **Missing map key errors.** `c.data["k"]` on a configmap with no `data` throws — guard
  with `has(c.data) && has(c.data["k"])` (or `"k" in c.data`).
- **Numbers from JSON** may be int or double; comparisons like `>= 2` are fine, but avoid
  mixing types in equality.
- **`celctl live` needs List-form expressions.** Each input is fetched via
  `kubectl get -o json` as a List; iterate with `.items`. (A single named object is
  wrapped into `{"items":[obj]}` so `.items` still works.)
