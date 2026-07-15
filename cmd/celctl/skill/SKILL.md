---
name: cel-rule
description: Author, lint, unit-test and live-evaluate ComplianceAsCode/content (cac-content) CEL rules with the celctl utility — no server required. Use when the user wants to write or fix a CEL rule under applications/<app>/<rule>/cel/, scaffold or run its cel/tests fixtures, check a rule against a live cluster, or ad-hoc test a CEL expression.
---

# CEL Rule

Helper for **Common Expression Language (CEL)** compliance rules in the
**ComplianceAsCode/content** (cac-content) repo — the shipping format for out-of-the-box
profiles: `applications/<app>/<rule>/cel/shared.yml` with unit-test fixtures in
`<rule-dir>/cel/tests/`. It drives **`celctl`** (shipped in the compliance-operator repo,
`cmd/celctl`), which evaluates expressions through the operator's own scanner engine
(compliance-sdk: cel-go + `parseJSON`/`parseYAML`, operator binding semantics,
`no such key` mapped to FAIL) — so what passes here behaves the same in the operator.

> **You do not evaluate CEL by hand.** Always round-trip every expression through
> `celctl`. Hand-reasoning about CEL semantics is unreliable; celctl is the source of
> truth, and it IS the operator's engine.

## Prerequisite: celctl on PATH

Check `celctl --help` (or `$CELCTL`). If missing, install it:

```bash
go install github.com/ComplianceAsCode/compliance-operator/cmd/celctl@latest
# from a compliance-operator checkout instead: make celctl  (build/_output/bin/celctl)
```

To update the tool: `go install github.com/ComplianceAsCode/compliance-operator/cmd/celctl@latest`.
The skill itself is installed by copying `cmd/celctl/skill` to `~/.claude/skills/cel-rule`
(see `cmd/celctl/README.md`). Live-cluster commands additionally require a kubeconfig
(`KUBECONFIG` or in-cluster).

## Binding semantics (critical — celctl mirrors the operator)

- input **with** `resource_name` → bound to the **single object**; reference it directly
  (`hco.spec.featureGates...`).
- input **without** `resource_name` → bound to a **List wrapper** `{items:[...]}`; you
  **must** iterate with `<name>.items.all(...)` / `.exists(...)` / `.filter(...)`.
  Writing `<name>.all(...)` is the #1 bug — it iterates map keys and fails at runtime.

## Workflow A — Author & validate a cac-content rule (no cluster)

The default loop for new or changed rules under `applications/<app>/<rule>/`.

1. **Clarify intent.** What resource(s)? What makes a resource compliant? Pin the
   namespace/scope and the exact field path.

2. **Write `cel/shared.yml`** (`check_type`, `failure_reason`, `inputs` with
   `kubernetes_input_spec`, `expression`) per
   [references/examples.md](references/examples.md) and the patterns in
   [references/cel-cookbook.md](references/cel-cookbook.md).

3. **Lint** (fast smoke test — catches the list/`.items` mistake and compile errors):
   ```bash
   celctl cac lint <rule-dir>
   # lint a whole app dir:
   for d in applications/openshift-virtualization/*/; do celctl cac lint "$d"; done
   ```
   `LINT FAILED: input "<name>" is a list … iterates it directly` → add `.items`.
   An `unguarded field access` warning is not a failure — a missing field makes the
   scanner report FAIL; add `has()` guards if absence should be compliant.

4. **Scaffold fixtures — never hand-invent resource shapes.** Schemas change across
   versions (HyperConverged `featureGates` is an object on v1beta1 but an array on v1;
   `nonRoot` was removed in 4.18+). With a cluster available, seed from real objects:
   ```bash
   celctl cac scaffold <rule-dir> --from-cluster   # real objects, sanitized, provenance-stamped
   celctl cac scaffold <rule-dir>                  # no cluster: skeleton, provenance says so
   ```
   The generated `cel/tests/cases.yaml` records **provenance** (fetch date, OpenShift/
   Kubernetes versions, the apiVersion actually served — versions only, never
   cluster-identifiable info). Fill the TODO cases by mutating only the interesting field.
   Checklist: compliant case, non-compliant case, empty/absent edge case (`all()` over
   `[]` is vacuously true!), provenance present.

5. **Unit-test the fixtures** (this is what content CI runs):
   ```bash
   celctl cac test <rule-dir>                      # auto-discovers cel/tests/*.yaml
   celctl cac test <rule-dir> --mock hcoList=hco.yaml --expect true   # one-shot
   ```
   Exit 0 only if every case matches. If a case is wrong, decide whether the
   *expression* or the *expectation* is mistaken, fix, re-run.
   Note: a `no such key` eval error counts as **FAIL** (with a warning), matching the
   scanner — not an execution error.

6. Report the final expression, inputs, and the passing case matrix. The content repo's
   CI (`tests/unit/kubernetes/test_cel_rules.py`) requires fixtures with at least one
   compliant and one non-compliant case per CEL rule.

## Workflow B — Run a rule against a live cluster

```bash
celctl cac live <rule-dir>
```
Fetches each input through the operator's real Kubernetes fetcher (client-go, honors
`KUBECONFIG`) and evaluates — the operator's own code path. Prints PASS/FAIL and the
rule's `failure_reason` on FAIL. If the result is surprising, `celctl samples <resource>`
the input and re-check the expression in Workflow A against that real data before blaming
the cluster.

## Workflow C — Ad-hoc expression checks

For quick experiments outside a rule dir (no `shared.yml` needed):

```bash
# evaluate once against local data (prints true/false):
celctl eval --expr 'pods.items.filter(p, p.spec.hostNetwork == true).size() == 0' --data pods=pods.json

# run a small expected-result matrix:
celctl verify --expr '<cel>' --test cases.json

# evaluate against the cluster:
celctl live --expr 'deployments.items.all(d, d.spec.replicas >= 2)' \
            --input deployments=apps/v1/deployments:production
```
Once the expression is right, put it in a rule dir and continue with Workflow A —
rules live in cac-content, not in ad-hoc files.

## Guardrails

- Never claim a CEL expression "works" without a passing `celctl cac test` /
  `cac live` result to back it up. Quote the `N/M cases passed` line.
- Never hand-invent resource shapes for fixtures — seed from `cac scaffold
  --from-cluster` or `celctl samples`; keep the provenance block.
- Guard optional fields with `has()`; remember the scanner turns missing-key errors
  into FAIL, not ERROR.
- Review fixtures for cluster-identifiable values before committing (versions are OK).

See [references/cel-cookbook.md](references/cel-cookbook.md) for CEL syntax patterns and
[references/examples.md](references/examples.md) for the shared.yml / fixture formats and
every celctl command.
