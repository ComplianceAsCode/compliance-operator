---
paths:
  - "**/*.go"
---

# Go Style — Compliance Operator

Applies to every Go file in the repo (excluding `vendor/`).

## Errors

- Return errors; never silently swallow.
- Wrap with `fmt.Errorf("...: %w", err)` when adding context. Don't double-wrap.
- Use `errors.Is` / `errors.As` for inspection.
- Don't put secrets, tokens, or kubeconfig contents in error messages.

## Logging

This repo uses `github.com/go-logr/logr` (controller-runtime convention). For test logs, use `framework.E2ELogf`, not `t.Log` — it routes through the framework's structured logger.

- Don't log at INFO for every reconcile — use V(1) or higher.
- Never log credentials, OAuth tokens, or full pod manifests.

## Concurrency

- Don't introduce package-level mutable globals. Where they already exist (`framework.Global`), don't shadow them.
- `wait.PollImmediate` / `wait.PollUntilContextTimeout` are the standard polling primitives. No `time.Sleep` in production code.

## Vendoring

- This repo uses `-mod=vendor`. Every new dep must land in `vendor/` via `go mod vendor`.
- Don't add a dependency for something the stdlib or existing deps already do.

## Generated code

- `zz_generated_*.go` and CRD manifests under `bundle/`, `config/crd/`, `config/manifests/` are produced by `make manifests generate`. Don't edit by hand.
- After CRD-type changes, run both: `make manifests generate`. Commit the resulting files alongside the trigger.

## boilerplate

- Existing files use a hashicorp/Red Hat header (see `custom-boilerplate.go.txt`). New `.go` files in `pkg/`, `cmd/`, `tests/` must carry it. Don't strip headers when reformatting.

## SDK upgrades

- The operator is on operator-sdk v1.x with controller-runtime v0.x — versions are pinned. Don't unilaterally bump them in a feature PR.
