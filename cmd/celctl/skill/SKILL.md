---
name: cel-rule
description: Author, validate, run, and manage Kubernetes CEL compliance rules with the local celctl utility — no server required. Use when the user wants to write a CEL expression/rule, test it against sample data or a live cluster, lint/unit-test ComplianceAsCode/content (cac-content) cel/shared.yml rules, or scaffold fixtures for new rules. Rules live in the cac-content repo.
---

# CEL Rule

End-to-end helper for **Common Expression Language (CEL)** rules that check Kubernetes
resources. It drives **`celctl`**, a CLI shipped in the compliance-operator repo (cmd/celctl) that evaluates CEL
locally with cel-go (the same engine the old `cel-rpc-server` used), and runs rules against a
live cluster via `kubectl`. Rules themselves live in the ComplianceAsCode/content repo.

> **This replaces the cel-rpc-server MCP server.** No server, no container, no AI keys.
> Everything is a local `celctl` invocation.

> **You do not evaluate CEL by hand.** Always round-trip every expression through `celctl`
> (`verify`/`eval`/`live`). Hand-reasoning about CEL semantics is unreliable; `celctl` is
> the source of truth.

## Prerequisite: celctl on PATH

The skill assumes a `celctl` binary exists (check `celctl --help`, or `$CELCTL`). If it
is missing, install it:

```bash
go install github.com/ComplianceAsCode/compliance-operator/cmd/celctl@latest
# from a compliance-operator checkout instead: make celctl  (build/_output/bin/celctl)
```

To update both the tool and this skill:
`go install github.com/ComplianceAsCode/compliance-operator/cmd/celctl@latest && celctl skill install`.
Live-cluster commands additionally require a working `kubectl` (current context = the
cluster you want to check).

## celctl command map (replaces the old MCP tools)

| Old MCP tool | celctl command |
|---|---|
| `verify_cel_with_tests` | `celctl verify --rule r.json` / `celctl verify --expr '<cel>' --test cases.json` |
| (ad-hoc single eval) | `celctl eval --expr '<cel>' --data var=data.json` |
| `verify_cel_live_resources` | `celctl live --rule r.json` / `celctl live --expr '<cel>' --input name=[group/]version/resource[:ns]` |
| `discover_resource_types` | `celctl discover` |
| `get_resource_samples` | `celctl samples <resource> [-n ns] [--max N]` |
| (cac-content rules) | `celctl cac lint\|test\|live <rule-dir>` — see Workflow C |

The old MCP rule-library tools (`add_rule`/`list_rules`/`get_rule`/`test_rule`/`remove_rule`)
have no replacement by design: rules live in the ComplianceAsCode/content repo
(`applications/<app>/<rule>/cel/shared.yml`) — use `celctl cac …` (Workflow C).

---

## Workflow A — Create & validate a rule (no cluster)

The default loop. Iterate here until the expression is correct, *then* optionally save it
or run it live.

1. **Clarify intent.** What resource(s)? What makes a resource compliant? Pin the
   namespace/scope and the exact field path.

2. **Pick the input shape.** Each input becomes a CEL variable bound to a Kubernetes
   **List** (`{"items":[...]}`). Decide the variable name and `version`/`resource`
   (`group` only for non-core types). Unsure of the real layout? Run
   `celctl samples <resource> -n <ns>` against a cluster and model your test data on it.

3. **Write the expression** per [references/cel-cookbook.md](references/cel-cookbook.md).
   The critical rule: data is List-wrapped, so iterate with `<var>.items.all(x, ...)` /
   `.exists(...)`.

4. **Write a rule file** (or a bare test-cases file) and run `celctl verify`. Include a
   happy-path case (`expected_result: true`), a failure case (`false`), and an empty-list
   edge case. Full file format: [references/examples.md](references/examples.md).

   ```bash
   celctl verify --rule myrule.json
   # or ad-hoc:
   celctl verify --expr 'pods.items.all(p, has(p.spec.securityContext) && p.spec.securityContext.runAsNonRoot == true)' \
                 --test cases.json
   ```

5. **Read the result.** `celctl` prints per-case PASS/FAIL and `N/M passed`, exiting non-zero
   if any case fails. If a case is wrong, decide whether the *expression* or the
   *expected_result* is mistaken, fix, and re-run. Mind the empty-list case: `all()` over
   `[]` is `true`, `exists()` over `[]` is `false` — make it match your intent.

6. Report the final expression, inputs, and the passing test matrix to the user.

## Workflow B — Run against a live cluster

Use when the user wants to know whether the *actual* cluster is compliant. Requires
`kubectl` pointed at the target cluster.

1. Optionally confirm the resource exists / is populated: `celctl discover` or
   `celctl samples <resource> -n <ns>`.
2. Run live. The expression must be List-form (`<var>.items.all(...)`) because each input
   is fetched as a List via `kubectl get -o json`.

   ```bash
   celctl live --rule myrule.json
   # or ad-hoc:
   celctl live --expr 'deployments.items.all(d, d.spec.replicas >= 2)' \
               --input deployments=apps/v1/deployments:production
   ```
   Input spec is `name=[group/]version/resource[:namespace]`; omit `:namespace` to query
   all namespaces (`-A`).
3. `celctl` prints how many items it fetched per input and a final PASS / FAIL
   (exit 0/1). If the result is surprising, `celctl samples` the resource and re-validate
   the expression in Workflow A against that real data before blaming the cluster.

## Workflow C — Validate ComplianceAsCode/content (cac-content) rules

Use this when the rules live in the **cac-content** repo as
`applications/<app>/<rule>/cel/shared.yml` (the shipping format for out-of-the-box
profiles). `celctl cac` understands that format natively and binds inputs **exactly like
the Compliance Operator scanner**, so what passes here behaves the same in the operator.

Binding semantics (critical — celctl mirrors the operator):
- input **with** `resource_name` → bound to the **single object**; reference it directly
  (`hco.spec.featureGates...`).
- input **without** `resource_name` → bound to a **List wrapper** `{items:[...]}`; you
  **must** iterate with `<name>.items.all(...)` / `.exists(...)` / `.filter(...)`.
  Writing `<name>.all(...)` is the #1 bug — it iterates map keys and fails at runtime.

1. **Lint** (fast smoke test — catches the list/`.items` mistake and compile errors):
   ```bash
   celctl cac lint applications/openshift-virtualization/kubevirt-nonroot-feature-gate-is-enabled
   # lint a whole app dir:
   for d in applications/openshift-virtualization/*/; do celctl cac lint "$d"; done
   ```
   A `LINT FAILED: input "<name>" is a list … but the expression iterates it directly`
   means a list input is being iterated without `.items`. Fix the expression and re-lint.
   An `unguarded field access` warning is not a failure — it means a missing field
   would make the scanner report FAIL; add `has()` guards if absence should be compliant.
   Note on semantics: `cac test`/`cac live` mirror the scanner — a `no such key` eval
   error counts as **FAIL** (with a warning), not an execution error.

2. **Scaffold fixtures — never hand-invent resource shapes.** Schemas change across
   versions (HyperConverged `featureGates` is an object on v1beta1 but an array on v1;
   `nonRoot` was removed in 4.18+), so a hand-written shape may not match what the API
   serves. With a cluster available, always seed from real objects:
   ```bash
   celctl cac scaffold <rule-dir> --from-cluster   # real objects, sanitized, provenance-stamped
   celctl cac scaffold <rule-dir>                  # no cluster: skeleton, provenance says so
   ```
   The generated `cel/tests/cases.yaml` records **provenance** (fetch date, OpenShift/
   Kubernetes versions, the apiVersion actually served per input — versions only, never
   cluster-identifiable info). Fill the TODO cases by mutating only the interesting field.
   Fixture checklist: compliant case, non-compliant case, empty/absent edge case,
   provenance present, `source_api_versions` matches the rule's input spec.

3. **Unit test** with fixtures (no cluster). Write a cases file and run `cac test`:
   ```bash
   celctl cac test <rule-dir> --cases cases.yaml
   ```
   `cases.yaml` is a list of `{name, expect, inputs}` where each input value is the raw
   resource data (a List `{items:[...]}` for list inputs, or the object for
   `resource_name` inputs — celctl normalizes either way). See
   [references/examples.md](references/examples.md) for a full example. celctl also
   auto-discovers `<rule-dir>/cel/tests/*.yaml` if you pass no `--cases`.

   Quick one-shot instead of a cases file:
   ```bash
   celctl cac test <rule-dir> --mock hcoList=hco.yaml --expect true
   ```

4. **Run against the cluster** (needs `kubectl`):
   ```bash
   celctl cac live <rule-dir>
   ```
   celctl fetches each input via `kubectl get` (single object when `resource_name` is set,
   else a List), evaluates, and prints PASS / FAIL with the rule's `failure_reason`.

Always `cac lint` first, then add fixtures and `cac test` for real true/false coverage,
then optionally `cac live` to check an actual cluster.

---

## Guardrails

- Never claim a CEL expression "works" without a passing `celctl verify`/`live` result to
  back it up. Quote the `N/M passed` line.
- Test data must be a List: `{"items":[...]}`. A bare object (no `items`) will not iterate.
- Guard optional fields with `has(x.field)` before dereferencing — a missing map key or
  field raises an eval error (surfaced as for that case).
- For `live`, the expression must be List-form; everything comes back wrapped in `items`.

See [references/cel-cookbook.md](references/cel-cookbook.md) for CEL syntax patterns and
[references/examples.md](references/examples.md) for the rule-file format and every
`celctl` command with example payloads.
