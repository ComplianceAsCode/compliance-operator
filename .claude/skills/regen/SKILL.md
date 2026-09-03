---
name: regen
description: Run the full Compliance Operator codegen pipeline after CRD-types edits — manifests, deepcopy, bundle, and verify the diff is the change you intended. Use after any edit under pkg/apis/.
---

# Regen

Stops the recurring "I forgot to regenerate" miss. Whenever you edit `pkg/apis/**/*_types.go`, several generated files become stale:

- `pkg/apis/**/zz_generated_deepcopy.go`
- `bundle/manifests/*.yaml`
- `config/crd/bases/*.yaml`
- `config/manifests/bases/*.yaml`

This skill runs the right `make` targets, then audits the resulting diff so you can sanity-check before committing.

## Arguments

```
/regen                    # full pipeline + diff audit
/regen --check            # dry-run: regenerate, then warn if any file changed and require a re-run before commit
/regen --bundle           # also regenerate the bundle layout (slower; only needed for releases)
```

---

## Preconditions

1. You've edited at least one `*_types.go` under `pkg/apis/`. If not, ask whether the skill is needed — most other Go edits don't require regeneration.
2. Working tree is acceptable to mutate (the targets write into generated files).

If a non-trivial uncommitted diff exists outside the `pkg/apis/` edit, ask before continuing — the skill must be able to attribute generated-file changes to the user's edit, not to leftover state.

---

## Workflow

### 1. Confirm what changed

```bash
git status -s -- pkg/apis/
git diff --stat HEAD -- pkg/apis/
```

If no `*_types.go` files have been touched (only test files, only generated files), suggest `make verify-bundle` is sufficient and stop.

### 2. Run codegen targets

In order:

```bash
make manifests
make generate
```

`make manifests` regenerates CRD YAMLs and RBAC. `make generate` regenerates DeepCopy methods. Both must be run; running one without the other leaves the tree inconsistent.

If `--bundle` was passed:

```bash
make verify-bundle
```

This regenerates the full operator bundle layout (CSV, OPM catalog refs, etc.). Heavyweight — only needed when preparing a release or when bundle/manifests/ specifically need updating.

### 3. Audit the diff

```bash
git status -s
git diff --stat
```

Now classify each modified file:

| File | What it means | Action |
|------|--------------|--------|
| `pkg/apis/**/zz_generated_deepcopy.go` | Field addition/rename → new DeepCopy methods | Expected. Include in commit. |
| `bundle/manifests/*.crd.yaml` | CRD schema changed | Expected. Include. |
| `config/crd/bases/*.yaml` | Same as above, different location | Expected. Include. |
| `config/manifests/bases/*.yaml` | CSV / OLM manifest updated | Expected. Include. |
| Any other file | NOT expected from a CRD edit | Investigate before committing. |

If `--check` was passed, the skill stops here and reports. Otherwise, continue.

### 4. Sanity-check the generated output

For each changed CRD YAML, verify your field actually appears in the schema:

```bash
grep -A 5 "<your-new-field>" bundle/manifests/*.crd.yaml
```

If it's not there, your kubebuilder marker on the type is malformed (common bug: missing `+kubebuilder:` prefix, wrong placement above the struct field).

### 5. Report

```markdown
## /regen report

Source edit: pkg/apis/.../<crd>_types.go (N fields touched)

Regenerated:
- N file(s) under pkg/apis/.../zz_generated_deepcopy.go
- N file(s) under bundle/manifests/
- N file(s) under config/crd/bases/
- N file(s) under config/manifests/bases/

Audit:
- all changes are expected codegen output
- new field <name> appears in bundle/manifests/<crd>.crd.yaml schema

Next: stage with `git add pkg/apis/ bundle/ config/` and commit alongside the trigger.
```

---

## Discipline

- **Always run both `make manifests` and `make generate`.** Skipping one leaves the tree in a broken state that CI will catch (`make verify-bundle` fails).
- **Don't commit the generated files in a separate commit from the trigger.** Reviewers can't tell whether the codegen is consistent without seeing both halves.
- **Don't manually edit zz_generated_*.go or bundle/manifests/*.yaml**. They get clobbered on next regen.
- If `make verify-bundle` fails after a clean regen, you likely have a `+kubebuilder:` marker problem. Read the error carefully — it usually points at the type.

## Related

- Rule: `.claude/rules/crd.md` — covers the kubebuilder markers and backwards-compat policy.
- Agent: `code-reviewer` — verifies generated files appear in the diff during PR review.
