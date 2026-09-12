---
paths:
  - "pkg/**/*_test.go"
---

# Unit Testing Rules — Compliance Operator

Applies to all unit tests under `pkg/`.

## Style

- Two flavors live in the repo:
  - **stdlib `testing`** (table-driven `t.Run`) — used in `pkg/utils/*_test.go`, `pkg/xccdf/strings_test.go`, `pkg/apis/.../*_test.go`.
  - **Ginkgo/Gomega** — used in `pkg/profileparser/`, `pkg/utils/celvalidation/`, `pkg/celcontent/`, `pkg/controller/customrule/`.
- Match the existing flavor in the package. Don't introduce Ginkgo into a stdlib package.

## File layout

- `<file>_test.go` colocated with `<file>.go`.
- A Ginkgo package has exactly one `<pkg>_suite_test.go` entry point. Don't add a second.

## Fakes / mocks

- Controllers: use `sigs.k8s.io/controller-runtime/pkg/client/fake` (`fake.NewClientBuilder().WithScheme(...).WithObjects(...)`).
- Kubernetes API objects: use the real types from `k8s.io/api/...`, not hand-rolled stubs.
- Don't add a mocking framework if the package doesn't already use one. If the existing package has hand-rolled fakes, extend them — don't introduce gomock.

## Scope

- Test only the code in the package under test. Don't re-test transitive behavior (controller-runtime's caching, etcd's writes) — assume the framework works.
- Don't write a test that requires a running API server. That's an integration concern; use envtest in a dedicated suite if needed, or push it down to e2e.

## Assertions

- stdlib: use `t.Errorf` / `t.Fatalf`, or `github.com/stretchr/testify/require`. Be consistent within the package.
- Ginkgo: use `Expect(x).To(Equal(y))` style.

## Running

```
make test-unit                         # all packages
go test ./pkg/<pkg>/... -count=1 -v    # single package, no cache
```

`-count=1` defeats Go's test cache when you need a clean run.

## Anti-patterns

- `t.Skip()` without a tracking issue link.
- Tests that mutate package-level state and forget to restore it.
- A `time.Sleep` to "wait for the goroutine to schedule" — that's a race smell, fix the seam.
