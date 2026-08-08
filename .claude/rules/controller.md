---
paths:
  - "pkg/controller/**"
---

# Controller Rules — Compliance Operator

Applies to anything under `pkg/controller/`.

## Reconciler shape

The standard reconciler flow in this repo:

1. Fetch the CR (`apierrors.IsNotFound` → return nil, nothing to do).
2. If `DeletionTimestamp` is set and we hold a finalizer, handle teardown and remove the finalizer.
3. Validate the spec. Invalid specs go to a terminal `Error` phase with a clear message — don't requeue them.
4. Reconcile child resources (Jobs, ConfigMaps, ScanSettings, etc.).
5. Update **status** with `r.Status().Update(ctx, obj)` — never `r.Update`. Status is a subresource.
6. Return `ctrl.Result{}` (no requeue) on success, or `RequeueAfter: ...` for periodic poll. Avoid `Requeue: true` without a delay — it's a tight loop.

## Status conventions

- Each top-level CRD has an enum `Phase` (e.g. `compv1alpha1.PhasePending`, `PhaseLaunching`, `PhaseRunning`, `PhaseAggregating`, `PhaseDone`).
- Set `Result` (`ResultCompliant` / `ResultNonCompliant` / `ResultError` / `ResultNotApplicable`) only when the phase reaches `Done`.
- Persist `ErrorMessage` when phase becomes `Error`.

## Children & ownership

- Always set `controllerutil.SetControllerReference(parent, child, r.Scheme)` so GC works.
- Owner refs can't cross namespaces — if you must reach across, use a label-based watch instead.

## Watches

- Top-level controllers watch their own CRD plus the children they own (Jobs, ConfigMaps, Pods for scans). New child types must be added to `SetupWithManager(...)` via `.Owns(...)` or `.Watches(...)`.

## RBAC

- Every API call needs a matching `+kubebuilder:rbac` marker on the reconciler. After adding one, run `make manifests` and confirm `config/rbac/role.yaml` was updated.

## Common pitfalls

- Reading a CR via cache vs API client: the cache may be stale. For writes, always use the live client (controller-runtime gives you one client; this isn't usually a concern, but be aware).
- Mutating a fetched object before update will hit a conflict if cache is behind — use `RetryOnConflict` for known-racy updates.
- Logging in a hot reconcile path floods journald. Use V(1)+ for non-error progress messages.
